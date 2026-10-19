#!/usr/bin/env python3
"""Install the reviewed OpenSSL 3 release in the Debian builder (container root only)."""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.parse
import urllib.request

from install import extract_archive

VERSION = "3.5.9"
SHA256 = "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"
URL = f"https://github.com/openssl/openssl/releases/download/openssl-{VERSION}/openssl-{VERSION}.tar.gz"
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
MAX_SOURCE_BYTES = 192 * 1024 * 1024


class ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        target = urllib.parse.urlsplit(new_url)
        if (
            target.scheme != "https"
            or target.hostname != "release-assets.githubusercontent.com"
            or target.port not in (None, 443)
            or target.username is not None
            or target.password is not None
        ):
            raise ValueError("Unexpected OpenSSL source redirect")
        return super().redirect_request(request, file, code, message, headers, new_url)


def main():
    if os.geteuid() != 0 or not Path("/etc/debian_version").is_file():
        raise SystemExit("Run this installer only as root inside the Debian builder container")
    request = urllib.request.Request(URL, headers={"User-Agent": "rauthy-build-tools"})
    with urllib.request.build_opener(ReleaseRedirect()).open(request, timeout=60) as response:
        data = response.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("OpenSSL source size or checksum mismatch")
    with tempfile.TemporaryDirectory(prefix="rauthy-builder-openssl-") as temporary:
        source = extract_archive(
            data, Path(temporary), f"openssl-{VERSION}", SHA256, MAX_SOURCE_BYTES
        )
        subprocess.run(
            ["./Configure", "--prefix=/usr/local", "--libdir=lib",
             "--openssldir=/usr/lib/ssl", "shared", "no-tests"],
            cwd=source, env={**os.environ, "CC": "clang"}, check=True,
        )
        subprocess.run(["make", "-j2"], cwd=source, check=True)
        subprocess.run(["make", "install_sw"], cwd=source, check=True)

    # Replace the libraries at the Debian loader paths too: changing PATH alone does not fix
    # Python's _ssl extension or other executables linked against libssl.so.3/libcrypto.so.3.
    multiarch = subprocess.check_output(["gcc", "-print-multiarch"], text=True).strip()
    if multiarch not in ("x86_64-linux-gnu", "aarch64-linux-gnu"):
        raise ValueError("Unsupported builder architecture")
    for name in ("libssl.so.3", "libcrypto.so.3"):
        destination = Path("/usr/lib") / multiarch / name
        if not destination.is_file():
            raise ValueError("Expected Debian OpenSSL library is missing")
        # Atomic replacement keeps this installer's already-mapped old library inode intact.
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as output:
            replacement = Path(output.name)
        try:
            shutil.copyfile(Path("/usr/local/lib") / name, replacement)
            replacement.chmod(0o644)
            replacement.replace(destination)
        finally:
            replacement.unlink(missing_ok=True)
    subprocess.run(["ldconfig"], check=True)
    # This process loaded the old SSL before installation; check in a fresh Python process.
    subprocess.run(["python3", str(Path(__file__).with_name("check_builder_tls.py"))], check=True)
    subprocess.run(["/usr/local/bin/openssl", "version"], check=True)


if __name__ == "__main__":
    main()
