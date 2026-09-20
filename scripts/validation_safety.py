"""Shared admission guard for local validation runners, not production runtime."""

import fcntl
import os
import shutil
import stat
from contextlib import contextmanager
from pathlib import Path

MIN_AVAILABLE_BYTES = 4 * 1024**3
MIN_DISK_BYTES = 5 * 1024**3


@contextmanager
def validation_slot(root: Path):
    """Serialize runners on this checkout and fail before starting lab resources.

    Keep the lock file: unlinking it could let another process lock a new inode.
    OS release on process exit also handles interrupted runs. This does not stop
    unrelated services or bound their future resource use.
    """
    shared = root / "shared"
    if not shared.is_dir() or shared.is_symlink():
        raise RuntimeError("validation_shared_directory_unavailable")
    fd = os.open(shared / ".validation.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            raise RuntimeError("validation_lock_unsafe")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("another_validation_is_running") from None
        memory = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
        if int(memory["MemAvailable"].split()[0]) * 1024 < MIN_AVAILABLE_BYTES:
            raise RuntimeError("validation_memory_reserve_insufficient")
        for path in (Path("/"), shared, Path("/var/lib/docker"), Path("/var/lib/containerd")):
            if path.exists() and shutil.disk_usage(path).free < MIN_DISK_BYTES:
                raise RuntimeError("validation_disk_reserve_insufficient")
        yield
    finally:
        os.close(fd)
