#!/usr/bin/env python3
"""Replace the builder's Cargo binary with the reviewed build using fixed system TLS."""

import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile

from install import DIRECTORY, in_builder_container, install


def main():
    if not in_builder_container():
        raise SystemExit("Run this bootstrap only as root inside the builder container")
    if not ssl.OPENSSL_VERSION.startswith("OpenSSL 3.5.9 "):
        raise ValueError("Install fixed builder OpenSSL before bootstrapping Cargo")
    spec = json.loads((DIRECTORY / "tools.json").read_text())["cargo"]
    target = Path("/tmp/rauthy-builder-cargo-target")
    with tempfile.TemporaryDirectory(prefix="rauthy-builder-cargo-") as temporary:
        root = Path(temporary)
        install("cargo", spec, root, target)
        binary = root / "bin/cargo"
        details = subprocess.check_output([str(binary), "-Vv"], text=True)
        print(details, flush=True)
        if (
            "cargo 1.95.0 (rauthy.1 reviewed TLS bootstrap)" not in details
            or "ssl:OpenSSL/3.5.9)" not in details
        ):
            raise ValueError("Rebuilt Cargo version or loaded TLS library is incorrect")
        destination = Path(subprocess.check_output(
            ["rustup", "which", "--toolchain", "1.95.0", "cargo"], text=True
        ).strip())
        if destination.name != "cargo" or destination.parent.name != "bin" or destination.is_symlink():
            raise ValueError("Unexpected rustup Cargo destination")
        # Keep the rustup dispatch shim: cargo +1.95.0 must select the patched binary as well.
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as output:
            replacement = Path(output.name)
        try:
            shutil.copyfile(binary, replacement)
            replacement.chmod(0o755)
            replacement.replace(destination)
        finally:
            replacement.unlink(missing_ok=True)
    subprocess.run(["cargo", "+1.95.0", "-Vv"], check=True)
    shutil.rmtree(target)


if __name__ == "__main__":
    main()
