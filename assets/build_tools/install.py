#!/usr/bin/env python3
"""Build pinned tool sources with the reviewed dependency locks in this directory."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import urllib.request

DIRECTORY = Path(__file__).resolve().parent
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        raise ValueError("Tool source download attempted a redirect")


def extract_archive(data, parent, prefix, checksum, max_source_bytes=None):
    if max_source_bytes is None:
        max_source_bytes = MAX_SOURCE_BYTES
    if hashlib.sha256(data).hexdigest() != checksum:
        raise ValueError(f"Archive checksum mismatch for {prefix}")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        seen = set()
        size = 0
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts:
                raise ValueError("Unsafe tool archive path")
            if path.parts[0] != prefix or "\\" in member.name:
                raise ValueError("Unexpected tool archive layout")
            if path.parts in seen or not (member.isdir() or member.isfile()):
                raise ValueError("Duplicate path, link, or special file in tool archive")
            seen.add(path.parts)
            size += member.size
            if member.size < 0 or size > max_source_bytes:
                raise ValueError("Tool archive exceeds source size limit")
        for member in members:
            target = parent.joinpath(*PurePosixPath(member.name).parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o700 if member.mode & 0o111 else 0o600)
    return parent / prefix


def extract_source(data, parent, name, version, checksum):
    source = extract_archive(data, parent, f"{name}-{version}", checksum)
    with (source / "Cargo.toml").open("rb") as file:
        package = tomllib.load(file)["package"]
    if package["name"] != name or package["version"] != version:
        raise ValueError("Tool package identity does not match the pinned archive")
    return source


def validate_lock(path, name, version):
    with path.open("rb") as file:
        packages = tomllib.load(file)["package"]
    roots = []
    for package in packages:
        if "source" not in package:
            roots.append((package["name"], package["version"]))
        elif package["source"] != REGISTRY or not re.fullmatch(
            r"[0-9a-f]{64}", package.get("checksum", "")
        ):
            raise ValueError("Tool lock contains an unpinned non-registry source")
    if roots != [(name, version)]:
        raise ValueError("Tool lock has unexpected local packages")


def install(name, spec, install_root, target_dir):
    if spec.get("builder_only") and not (
        os.geteuid() == 0 and (Path("/.dockerenv").exists() or Path("/run/.containerenv").exists())
    ):
        raise ValueError("This tool bootstrap is only for the builder container")
    lock = DIRECTORY / "locks" / f"{name}.Cargo.lock"
    validate_lock(lock, name, spec["installed_version"])
    url = f"https://static.crates.io/crates/{name}/{name}-{spec['version']}.crate"
    print(f"Installing {name} {spec['installed_version']} from verified source", flush=True)
    request = urllib.request.Request(url, headers={"User-Agent": "rauthy-build-tools"})
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(request, timeout=60) as response:
        data = response.read(MAX_ARCHIVE_BYTES + 1)
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError("Tool archive exceeds download size limit")
    with tempfile.TemporaryDirectory(prefix="rauthy-build-tool-") as temporary:
        source = extract_source(
            data, Path(temporary), name, spec["version"], spec["sha256"]
        )
        if "patch" in spec:
            subprocess.run(
                ["patch", "--batch", "--fuzz=0", "-p1", "--input", str(DIRECTORY / spec["patch"])],
                cwd=source,
                check=True,
            )
        with (source / "Cargo.toml").open("rb") as file:
            if tomllib.load(file)["package"]["version"] != spec["installed_version"]:
                raise ValueError("Patched tool version does not match its lock")
        shutil.copyfile(lock, source / "Cargo.lock")
        command = ["cargo", "+1.95.0", "install", "--path", str(source), "--locked", "--force"]
        if "features" in spec:
            command.extend(["--no-default-features", "--features", ",".join(spec["features"])])
        if install_root:
            command.extend(["--root", str(install_root.resolve())])
        environment = os.environ.copy()
        environment.update(
            CARGO_BUILD_JOBS="1",
            CARGO_PROFILE_RELEASE_LTO="false",
            CARGO_PROFILE_RELEASE_CODEGEN_UNITS="16",
        )
        environment.update(spec.get("build_environment", {}))
        if target_dir:
            environment["CARGO_TARGET_DIR"] = str(target_dir.resolve())
        subprocess.run(command, cwd=source, env=environment, check=True)


def main():
    tools = json.loads((DIRECTORY / "tools.json").read_text())
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, help="Optional Cargo binary installation root")
    parser.add_argument("--target-dir", type=Path, help="Shared task-owned build directory")
    parser.add_argument("tools", nargs="+", choices=tools)
    arguments = parser.parse_args()
    for name in arguments.tools:
        install(name, tools[name], arguments.root, arguments.target_dir)


if __name__ == "__main__":
    main()
