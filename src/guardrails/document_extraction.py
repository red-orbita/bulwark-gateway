"""Bounded local text extraction with default Bubblewrap parser isolation.

Only invoke on hostile documents inside an operator-provisioned parser-isolated
deployment; see docs/DOCUMENT-EXTRACTION.md. No optional Python parser packages.
"""

from __future__ import annotations

import asyncio
import math
import os
import queue
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator, Literal

MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_TEXT_BYTES = 32 * 1024
MAX_PIXELS = 8_000_000
MAX_DIMENSION = 8000
MAX_PAGES = 5
PROCESS_TIMEOUT_SECONDS = 20.0
DOCUMENT_TIMEOUT_SECONDS = 90.0
MAX_RENDER_BYTES = 32 * 1024 * 1024
_BINARIES = {name: f"/usr/bin/{name}" for name in ("tesseract", "pdfinfo", "pdftoppm", "pdftotext")}
_BWRAP = "/usr/bin/bwrap"
_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="document-extraction")
_PNG = b"\x89PNG\r\n\x1a\n"
_CAPACITY: queue.SimpleQueue[object] = queue.SimpleQueue()
for _ in range(2):
    _CAPACITY.put(object())

ExtractionReason = Literal[
    "unsupported_mime", "invalid_document", "input_limit", "pixel_limit",
    "page_limit", "encrypted_pdf", "output_limit", "no_text", "busy",
    "timeout", "unavailable", "invalid_languages", "extraction_failed", "incomplete",
]


class ExtractionError(Exception):
    """Safe reason only: never includes document content, paths or tool stderr."""

    def __init__(self, reason: ExtractionReason) -> None:
        self.reason = reason
        super().__init__(reason)


# Constant program, not generated from document data. Limits are applied in a
# fresh isolated interpreter BEFORE exec, never via preexec_fn in a thread.
_WORKER = """
import os, resource, sys
allowed = {'/usr/bin/tesseract', '/usr/bin/pdfinfo', '/usr/bin/pdftoppm', '/usr/bin/pdftotext'}
binary = sys.argv[2]
if binary not in allowed:
    sys.exit(126)
for kind, limit in (
    (resource.RLIMIT_CPU, 15),
    (resource.RLIMIT_AS, 768 * 1024 * 1024),
    (resource.RLIMIT_FSIZE, int(sys.argv[1])),
    (resource.RLIMIT_NOFILE, 64),
    (resource.RLIMIT_CORE, 0),
):
    resource.setrlimit(kind, (limit, limit))
os.umask(0o077)
with open('.worker-ready', 'xb'):
    pass
os.execve(binary, sys.argv[2:], dict(os.environ))
"""


def _check_pixels(width: int, height: int) -> None:
    if not (0 < width <= MAX_DIMENSION and 0 < height <= MAX_DIMENSION and width * height <= MAX_PIXELS):
        raise ExtractionError("pixel_limit")


def _image_geometry(data: bytes, mime: str) -> None:
    """Structural/geometry preflight only; native decoders still handle pixels."""
    if mime == "image/png":
        if not data.startswith(_PNG) or len(data) < 33 or data[8:16] != b"\x00\x00\x00\rIHDR":
            raise ExtractionError("invalid_document")
        _check_pixels(*struct.unpack_from(">II", data, 16))
        offset, image_data = 8, False
        while offset + 12 <= len(data):
            size = int.from_bytes(data[offset:offset + 4], "big")
            end = offset + 12 + size
            if end > len(data):
                break
            kind = data[offset + 4:offset + 8]
            if zlib.crc32(data[offset + 4:end - 4]) != int.from_bytes(data[end - 4:end], "big"):
                break
            if kind == b"acTL" or (kind == b"IHDR" and offset != 8):
                break  # Animated images cannot be reduced to just their first frame.
            image_data |= kind == b"IDAT"
            if kind == b"IEND":
                if size == 0 and end == len(data) and image_data:
                    return
                break
            offset = end
        raise ExtractionError("invalid_document")

    if not data.startswith(b"\xff\xd8\xff") or not data.endswith(b"\xff\xd9"):
        raise ExtractionError("invalid_document")
    offset, dimensions = 2, None
    while offset + 4 <= len(data):
        if data[offset] != 0xFF:
            break
        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset + 3 > len(data):
            break
        marker = data[offset]
        size = int.from_bytes(data[offset + 1:offset + 3], "big")
        if size < 2 or offset + 1 + size > len(data):
            break
        if marker in (0xC0, 0xC1, 0xC2):
            if dimensions is not None or size < 8:
                break
            height, width = struct.unpack_from(">HH", data, offset + 4)
            _check_pixels(width, height)
            dimensions = (width, height)
        elif 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            break  # Unsupported SOF variants must not bypass the geometry gate.
        if marker == 0xDA:
            if dimensions is not None:
                return
            break
        offset += 1 + size
    raise ExtractionError("invalid_document")


@contextmanager
def _regular_file(path: Path, *, create: bool = False) -> Iterator[BinaryIO]:
    """Never follow parser-created links or block opening a special file.

    The parent is the private mount root under an operator-controlled directory;
    the parser cannot change its ancestors. Pin it before touching child names.
    """
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        flags = os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        if create:
            try:
                os.unlink(path.name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            # Never truncate an existing inode, including a hardlink. If an
            # entry races the unlink, O_EXCL fails rather than opening it.
            flags |= os.O_RDWR | os.O_CREAT | os.O_EXCL
        else:
            flags |= os.O_RDONLY
        fd = os.open(path.name, flags, 0o600, dir_fd=directory_fd)
        with os.fdopen(fd, "w+b" if create else "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ExtractionError("invalid_document")
            yield handle
    finally:
        os.close(directory_fd)


def _unlink_file(path: Path) -> None:
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        try:
            os.unlink(path.name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
    finally:
        os.close(directory_fd)


def _read_bounded(path: Path, limit: int) -> bytes:
    try:
        with _regular_file(path) as handle:
            data = handle.read(limit + 1)
    except OSError:
        raise ExtractionError("invalid_document") from None
    if len(data) > limit:
        raise ExtractionError("output_limit")
    return data


def _run(
    tool: str, args: list[str], directory: Path, stop: threading.Event, deadline: float,
    *, render: bool = False, sandbox: bool = True,
) -> bytes:
    """Runs in the bounded extraction thread; owns and reaps every child."""
    if stop.is_set() or time.monotonic() >= deadline:
        raise ExtractionError("timeout")
    binary = _BINARIES[tool]
    if not os.access(binary, os.X_OK) or (sandbox and not os.access(_BWRAP, os.X_OK)):
        raise ExtractionError("unavailable")
    env = {
        "PATH": "/usr/bin", "HOME": "/work" if sandbox else str(directory),
        "TMPDIR": "/work" if sandbox else str(directory),
        "LC_ALL": "C", "OMP_THREAD_LIMIT": "1", "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
    }
    limit = MAX_RENDER_BYTES if render else MAX_TEXT_BYTES + 1
    end = min(deadline, time.monotonic() + PROCESS_TIMEOUT_SECONDS)
    ready = directory / ".worker-ready"
    _unlink_file(ready)
    command = [sys.executable, "-I", "-c", _WORKER, str(limit), binary, *args]
    if sandbox:
        # Poppler's base-font fallback needs fontconfig, but not host /etc or
        # user font configuration. Fonts are already in the read-only runtime.
        with _regular_file(directory / "fonts.conf", create=True) as fonts:
            fonts.write(b'<?xml version="1.0"?><fontconfig><dir>/usr/share/fonts</dir>'
                        b'<cachedir>/work/font-cache</cachedir></fontconfig>')
        env["FONTCONFIG_FILE"] = "/work/fonts.conf"
        # Only internally generated document paths are rewritten. Never expose
        # sys.executable's virtualenv (which may live alongside repository secrets).
        mapped = [str(Path("/work") / Path(arg).relative_to(directory))
                  if arg.startswith(str(directory) + "/") else arg for arg in args]
        command = [
            _BWRAP, "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
            "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib",
            "--ro-bind", "/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev",
            "--tmpfs", "/tmp", "--bind", str(directory), "/work", "--chdir", "/work",  # noqa: S108 - private namespace
        ]
        if Path("/etc/ld.so.cache").is_file():
            command.extend(["--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache"])
        command.extend(["/usr/bin/python3", "-I", "-c", _WORKER, str(limit), binary, *mapped])
    stdout, stderr = directory / "stdout", directory / "stderr"
    with _regular_file(stdout, create=True) as out, _regular_file(stderr, create=True) as err:
        process = subprocess.Popen(  # noqa: S603 - fixed executable/program, no shell; validated arguments
            command,
            stdin=subprocess.DEVNULL, stdout=out, stderr=err,
            cwd=directory, env=env, start_new_session=True, close_fds=True,
        )
        try:
            while process.poll() is None:
                if stop.is_set() or time.monotonic() >= end:
                    raise ExtractionError("timeout")
                stop.wait(0.025)
        finally:
            # Kill remaining same-group descendants even if the leader exited.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # Group already exited; the leader still must be reaped.
            process.wait()
        if stop.is_set() or time.monotonic() >= end:
            raise ExtractionError("timeout")
        if sandbox:
            try:
                _read_bounded(ready, 0)
            except ExtractionError:
                raise ExtractionError("unavailable") from None
        if process.returncode != 0:
            raise ExtractionError("extraction_failed")
        # Retain the trusted descriptors: parser-controlled stdout/stderr names
        # may now be symlinks, FIFOs or different inodes. Never reopen/stat them.
        out.seek(0)
        result = out.read(MAX_TEXT_BYTES + 1)
        if len(result) > MAX_TEXT_BYTES:
            raise ExtractionError("output_limit")
        # Poppler warnings may indicate a partial parse. Tesseract's bounded
        # resolution diagnostics are discarded without inspecting their content.
        if tool != "tesseract" and os.fstat(err.fileno()).st_size:
            raise ExtractionError("invalid_document")
        return result


def _extract(
    data: bytes, mime: str, work_dir: Path, languages: str, stop: threading.Event, sandbox: bool,
) -> str:
    deadline = time.monotonic() + DOCUMENT_TIMEOUT_SECONDS
    try:
        if mime != "application/pdf":
            _image_geometry(data, mime)
        elif not re.match(rb"%PDF-[12]\.[0-9](?:\r|\n)", data):
            raise ExtractionError("invalid_document")
        # No fallback to the system temp directory, nor implicit parent creation.
        if not work_dir.is_absolute() or not work_dir.is_dir() or not shutil.rmtree.avoids_symlink_attacks:
            raise ExtractionError("unavailable")
        with tempfile.TemporaryDirectory(prefix="document-", dir=work_dir) as temp:
            directory = Path(temp)
            source = directory / {"application/pdf": "source.pdf", "image/png": "source.png",
                                  "image/jpeg": "source.jpg"}[mime]
            with _regular_file(source, create=True) as original:
                original.write(data)
            available = _run("tesseract", ["--list-langs"], directory, stop, deadline,
                             sandbox=sandbox).decode("utf-8")
            if not set(languages.split("+")) <= set(available.splitlines()[1:]):
                raise ExtractionError("unavailable")
            if mime != "application/pdf":
                text = _run("tesseract", [str(source), "stdout", "-l", languages, "--psm", "6"],
                            directory, stop, deadline, sandbox=sandbox).decode("utf-8")
                if not text.strip():
                    raise ExtractionError("no_text")
                return text

            info = _run("pdfinfo", ["-f", "1", "-l", str(MAX_PAGES), "-box", str(source)],
                        directory, stop, deadline, sandbox=sandbox).decode("utf-8")
            counts = re.findall(r"^Pages:\s*([0-9]{1,9})\s*$", info, re.MULTILINE)
            encryption = re.findall(r"^Encrypted:[^\r\n]*", info, re.MULTILINE)
            if len(counts) != 1 or len(encryption) != 1:
                raise ExtractionError("invalid_document")
            if not re.fullmatch(r"Encrypted:[ \t]+no[ \t]*", encryption[0]):
                raise ExtractionError("encrypted_pdf")
            pages = int(counts[0])
            if not 1 <= pages <= MAX_PAGES:
                raise ExtractionError("page_limit")
            sizes = re.findall(
                r"^Page\s+([0-9]+) size:\s+([0-9.]+) x ([0-9.]+) pts[^\r\n]*$", info, re.MULTILINE,
            )
            if len(sizes) != pages or [int(row[0]) for row in sizes] != list(range(1, pages + 1)):
                raise ExtractionError("invalid_document")
            for _, width, height in sizes:
                _check_pixels(math.ceil(float(width) * 150 / 72), math.ceil(float(height) * 150 / 72))

            combined = bytearray()
            for page in range(1, pages + 1):
                number = str(page)
                embedded = _run("pdftotext", ["-f", number, "-l", number, "-enc", "UTF-8", "-layout",
                                             str(source), "-"], directory, stop, deadline, sandbox=sandbox)
                _run("pdftoppm", ["-f", number, "-l", number, "-singlefile", "-r", "150",
                                  "-scale-to", "2800", "-png", str(source), str(directory / "page")],
                     directory, stop, deadline, render=True, sandbox=sandbox)
                image = directory / "page.png"
                rendered = _read_bounded(image, MAX_RENDER_BYTES)
                _image_geometry(rendered, "image/png")
                visual = _run("tesseract", [str(image), "stdout", "-l", languages, "--psm", "6"],
                              directory, stop, deadline, sandbox=sandbox)
                _unlink_file(image)
                embedded_text, visual_text = embedded.decode("utf-8"), visual.decode("utf-8")
                if not visual_text.strip():
                    # A readable neighbour or hidden text must not mask a page
                    # whose rendered view could not be inspected through OCR.
                    raise ExtractionError("incomplete" if embedded_text.strip() else "no_text")
                for label, content in (("embedded", embedded), ("OCR", visual)):
                    section = f"\n[Page {page}: {label} text]\n".encode() + content
                    if len(combined) + len(section) > MAX_TEXT_BYTES:
                        raise ExtractionError("output_limit")
                    combined.extend(section)
            return combined.decode("utf-8")
    except ExtractionError:
        raise
    except (OSError, ValueError, RuntimeError, OverflowError, struct.error):
        raise ExtractionError("extraction_failed") from None


async def extract_document(
    data: bytes, mime: str, *, work_dir: Path, languages: str = "eng", sandbox: bool = True,
) -> str:
    """Return ONLY untrusted extracted text, or raise a safe ExtractionError.

    ``work_dir`` (existing absolute persistent directory), ``languages`` and ``sandbox`` are
    operator settings, not client options. Two active calls per Python process;
    excess callers fail immediately, including across event loops/threads.
    Cancellation does not release capacity until the worker and child are done.
    """
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_INPUT_BYTES:
        raise ExtractionError("input_limit")
    if mime not in ("image/png", "image/jpeg", "application/pdf"):
        raise ExtractionError("unsupported_mime")
    if not isinstance(languages, str) or not re.fullmatch(
        r"[a-z][a-z0-9_]{1,31}(?:\+[a-z][a-z0-9_]{1,31}){0,2}", languages,
    ):
        raise ExtractionError("invalid_languages")
    if not isinstance(work_dir, Path) or not isinstance(sandbox, bool):
        raise ExtractionError("unavailable")
    try:
        token = _CAPACITY.get_nowait()
    except queue.Empty:
        raise ExtractionError("busy") from None
    stop = threading.Event()
    try:
        future = _EXECUTOR.submit(_extract, data, mime, work_dir, languages, stop, sandbox)
    except RuntimeError:
        _CAPACITY.put(token)
        raise ExtractionError("unavailable") from None
    # Admission belongs to the actual worker, not an asyncio wrapper that loop
    # shutdown may cancel. This callback also runs after the originating loop closes.
    future.add_done_callback(lambda _: _CAPACITY.put(token))
    wrapped = asyncio.wrap_future(future)
    wrapped.add_done_callback(lambda result: None if result.cancelled() else result.exception())
    try:
        return await asyncio.shield(wrapped)
    except asyncio.CancelledError:
        stop.set()
        while not future.done() and not wrapped.cancelled():
            try:
                await asyncio.shield(wrapped)
            except asyncio.CancelledError:
                continue
            except Exception:
                break  # Exception retrieved by callback; propagate cancellation.
        raise
