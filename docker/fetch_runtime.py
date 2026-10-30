"""Build-only hash-locked APK fetcher. APK verifies vendor signatures separately.

No extraction, execution, credential handling or ambient proxy use. A missing or
changed artifact fails the build; dependencies are never resolved from latest.
"""

import hashlib
import re
import shutil
import ssl
import sys
import urllib.request
from pathlib import Path

REPOSITORY = "https://packages.wolfi.dev/os/x86_64/"
# Signed index snapshot; APK verifies its signature and each package checksum.
INDEX_SHA256 = "d62b4fdf0139097b7b24f42f19d325517fb2cb6d403cd52941f3f9d3aac49188"
MAX_APK_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Package redirects are not allowed")


def fetch(lock: Path, destination: Path) -> None:
    text = lock.read_text(encoding="ascii")
    if len(text) > 32768:
        raise ValueError("Runtime lock exceeds budget")
    entries = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([a-f0-9]{64})  ([a-z0-9][a-z0-9.+_-]*\.apk)", line)
        if not match or ".." in match[2]:
            raise ValueError("Invalid runtime lock")
        entries.append(match.groups())
    if not 1 <= len(entries) <= 128 or len({name for _, name in entries}) != len(entries):
        raise ValueError("Invalid runtime package set")
    tls = ssl.create_default_context()
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                       urllib.request.HTTPSHandler(context=tls))
    destination.mkdir(parents=True, exist_ok=False)
    index = lock.with_name("wolfi-APKINDEX.tar.gz")
    if index.stat().st_size > MAX_APK_BYTES or hashlib.sha256(index.read_bytes()).hexdigest() != INDEX_SHA256:
        raise ValueError("Signed index snapshot mismatch")
    shutil.copyfile(index, destination / "APKINDEX.tar.gz")
    specs = []
    for _, name in entries:
        match = re.fullmatch(r"(.+)-([0-9][^-]*-r[0-9]+)\.apk", name)
        if not match:
            raise ValueError("Invalid package version")
        specs.append(f"{match[1]}={match[2]}")
    (destination / "packages.txt").write_text("\n".join(specs) + "\n", encoding="ascii")
    total = 0
    for digest, name in entries:
        size = 0
        calculated = hashlib.sha256()
        with opener.open(REPOSITORY + name, timeout=30) as response, (destination / name).open("xb") as output:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise ValueError("Invalid package response")
            while chunk := response.read(65536):
                size += len(chunk)
                total += len(chunk)
                if size > MAX_APK_BYTES or total > MAX_TOTAL_BYTES:
                    raise ValueError("Runtime packages exceed budget")
                calculated.update(chunk)
                output.write(chunk)
        if calculated.hexdigest() != digest:
            raise ValueError("Runtime package digest mismatch")


if __name__ == "__main__":
    fetch(Path(sys.argv[1]), Path(sys.argv[2]))
