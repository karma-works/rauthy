"""Exercise the bootstrap's source and lock trust boundaries without network or Cargo."""

import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import install


def archive_bytes(entries):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for name, kind, content in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = len(content) if kind == tarfile.REGTYPE else 0
            archive.addfile(member, io.BytesIO(content) if member.isfile() else None)
    return data.getvalue()


MANIFEST = b'[package]\nname = "example"\nversion = "1.0.0"\n'
VALID = [("example-1.0.0/Cargo.toml", tarfile.REGTYPE, MANIFEST)]
LOCK = 'version = 4\n[[package]]\nname = "example"\nversion = "1.0.0"\n'


class BootstrapTests(unittest.TestCase):
    def extract(self, entries):
        data = archive_bytes(entries)
        with tempfile.TemporaryDirectory() as temporary:
            return install.extract_source(
                data, Path(temporary), "example", "1.0.0", hashlib.sha256(data).hexdigest()
            )

    def test_valid_archive(self):
        self.extract(VALID)

    def test_checksum_precedes_archive_parsing(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                install.extract_source(b"not a tar", Path(temporary), "example", "1", "0" * 64)
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_archive_paths_and_file_types(self):
        for name, kind in [
            ("/example-1.0.0/file", tarfile.REGTYPE),
            ("example-1.0.0/../file", tarfile.REGTYPE),
            ("different-1.0.0/file", tarfile.REGTYPE),
            ("example-1.0.0\\file", tarfile.REGTYPE),
            ("example-1.0.0/link", tarfile.SYMTYPE),
            ("example-1.0.0/hardlink", tarfile.LNKTYPE),
            ("example-1.0.0/device", tarfile.CHRTYPE),
        ]:
            with self.subTest(name=name, kind=kind), self.assertRaises(ValueError):
                self.extract(VALID + [(name, kind, b"")])

    def test_normalized_duplicate_paths(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.extract(VALID + [("example-1.0.0/./Cargo.toml", tarfile.REGTYPE, MANIFEST)])

    def test_source_size_limit(self):
        with patch.object(install, "MAX_SOURCE_BYTES", 1), self.assertRaises(ValueError):
            self.extract(VALID)

    def test_wrong_package_identity(self):
        with self.assertRaisesRegex(ValueError, "identity"):
            self.extract([("example-1.0.0/Cargo.toml", tarfile.REGTYPE, MANIFEST.replace(b"example", b"other"))])

    def test_lock_rejects_git_unchecksummed_and_local_sources(self):
        bad = [
            '[[package]]\nname="dep"\nversion="1"\nsource="git+https://example.org/dep"\n',
            '[[package]]\nname="dep"\nversion="1"\nsource="' + install.REGISTRY + '"\n',
            '[[package]]\nname="dep"\nversion="1"\n',
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "Cargo.lock"
            for entry in bad:
                with self.subTest(entry=entry), self.assertRaises(ValueError):
                    path.write_text(LOCK + entry)
                    install.validate_lock(path, "example", "1.0.0")
            path.write_text(LOCK)
            install.validate_lock(path, "example", "1.0.0")

    def test_source_redirects_rejected(self):
        with self.assertRaisesRegex(ValueError, "redirect"):
            install.NoRedirect().redirect_request(None, None, 302, "", {}, "http://example.org")

    def test_relative_install_root_resolved_before_cargo(self):
        data = archive_bytes(VALID)
        spec = dict(version="1.0.0", installed_version="1.0.0", sha256=hashlib.sha256(data).hexdigest())
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "locks").mkdir()
            (directory / "locks/example.Cargo.lock").write_text(LOCK)
            with patch.object(install, "DIRECTORY", directory), patch.object(
                install.urllib.request, "build_opener"
            ) as opener, patch.object(install.subprocess, "run") as run:
                opener.return_value.open.return_value = io.BytesIO(data)
                install.install("example", spec, Path("temporary-tools"), Path("temporary-target"))
                command = run.call_args.args[0]
                self.assertEqual(command[command.index("--root") + 1], str(Path("temporary-tools").resolve()))
                self.assertIn("--locked", command)
                self.assertEqual(command[:2], ["cargo", "+1.95.0"])
                self.assertEqual(run.call_args.kwargs["env"]["CARGO_BUILD_JOBS"], "1")

    def test_builder_only_tool_rejected_before_download(self):
        with patch.object(install.os, "geteuid", return_value=1000), patch.object(
            install.urllib.request, "build_opener"
        ) as opener, self.assertRaisesRegex(ValueError, "builder container"):
            install.install("cargo", {"builder_only": True}, None, None)
        opener.assert_not_called()

    def test_native_tls_build_flags_disable_default_vendoring(self):
        data = archive_bytes(VALID)
        spec = dict(
            version="1.0.0", installed_version="1.0.0", sha256=hashlib.sha256(data).hexdigest(),
            features=["http-transport-curl", "vendored-libgit2"],
            build_environment={"OPENSSL_NO_VENDOR": "1"},
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "locks").mkdir()
            (directory / "locks/example.Cargo.lock").write_text(LOCK)
            with patch.object(install, "DIRECTORY", directory), patch.object(
                install.urllib.request, "build_opener"
            ) as opener, patch.object(install.subprocess, "run") as run:
                opener.return_value.open.return_value = io.BytesIO(data)
                install.install("example", spec, None, None)
                command = run.call_args.args[0]
                self.assertIn("--no-default-features", command)
                self.assertEqual(command[command.index("--features") + 1], "http-transport-curl,vendored-libgit2")
                self.assertEqual(run.call_args.kwargs["env"]["OPENSSL_NO_VENDOR"], "1")


if __name__ == "__main__":
    unittest.main()
