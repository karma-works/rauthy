# Reviewed build tools

Run `python3 assets/build_tools/install.py TOOL...` from the repository root. Python 3.11+, `patch`,
and Rust 1.95.0 through rustup are required. Optional `--root PATH` sets the Cargo binary
installation root; `--target-dir PATH` shares compilation artifacts across tools. Compilation uses
one job and disables release LTO to keep developer machines with limited memory usable.

| Tool | Source version | Installed version |
| --- | --- | --- |
| just | 1.58.0 | 1.58.0 |
| wasm-pack | 0.15.0 | 0.15.0-rauthy.1 |
| wasm-bindgen-cli | 0.2.129 | 0.2.129 |
| mdbook | 0.4.52 | 0.4.52 |
| mdbook-admonish | 1.20.0 | 1.20.0 |
| cargo (builder only) | 0.96.0 | 1.95.0 CLI, rauthy.1 build |

The installer downloads only the exact static.crates.io source archive named in `tools.json`.
Redirects are rejected. Its SHA-256, verified against the official crates.io version metadata,
must match before extraction or execution. Extraction rejects traversal, links, special files,
duplicate paths, and unexpected package identities. Reviewed Cargo locks permit only the local
tool package and checksum-pinned crates.io dependencies; Cargo always runs with `--locked`.

Published tool locks can contain vulnerable dependencies even when their root version is current.
The checked-in locks update affected TLS, HTML sanitization, bytes, slab, and crossbeam
dependencies.
mdbook-admonish uses compatible mdbook 0.4.52, removing the old h2 server dependency. The small
`wasm-pack-no-update.patch` disables the upstream CLI's unconditional background version-check
request and adds the local version suffix. It is applied to verified source with zero patch fuzz.
Other explicit wasm-pack commands keep their upstream behavior; repository builds use
`--mode no-install`, a matching wasm-bindgen CLI, and disabled optional wasm-opt.

These pins make inputs reviewable, but do not prove that dependencies are free of defects.
Recheck RustSec advisories when refreshing them. Informational notices about unmaintained crates
must be assessed separately from known security advisories; they are not silently ignored by an
audit configuration. The reviewed wasm-pack lock retains an scc notice in dev-only test
dependencies. The wasm-bindgen CLI retains upstream unmaintained buf_redux, multipart, safemem,
and twoway notices.
The installed tool graphs have no known security advisories at the time of this review.

The bookworm OpenSSL package lacks a fix for
[CVE-2026-35189](https://security-tracker.debian.org/tracker/CVE-2026-35189).
After signed APT upgrades, both builders run `builder_openssl.py` as container root to compile
unmodified official [OpenSSL 3.5.9](https://openssl-library.org/news/openssl-3.5-notes/) source.
The native compiler is Clang from the same signed snapshot; two compilation jobs bound resource use.
The archive URL and SHA-256 are pinned in the installer and verified before extraction or
execution. GitHub redirects are restricted to its HTTPS release-asset host. The release API's
archive digest is
`603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a`.
Extraction rejects traversal, links, duplicate paths, and special files and bounds source size.

OpenSSL 3 preserves its major-version ABI. Installation replaces both Debian loader-path shared
libraries atomically and installs the CLI, headers, and providers under `/usr/local`. This fixes
Python's actual TLS library as well as other dynamically linked builder tools; changing `PATH`
alone would not do so. Debian's CA store stays in use, and a fresh Python process checks the loaded
version and trust store. Install all APT packages before this replacement: subsequent APT OpenSSL
updates could overwrite it. The inherited dpkg version records still describe the Debian package;
package-version-only scanners cannot identify this upstream replacement. The server separately uses
vendored OpenSSL 4.0.3 described in `vendor/README.md`.
`just build` constructs this patched builder from `Dockerfile_builder` and runs its immutable image
ID for both cross-compilation targets, rather than executing the inherited GHCR image directly.
Node 26.11.1 is pinned in the image, CI, and `frontend/.nvmrc`; its embedded OpenSSL is also 3.5.9.
Cargo's embedded copy is replaced separately by `builder_cargo.py` using reviewed source and a lock;
see [Cargo bootstrap](CARGO.md). Rust 1.95 stays pinned, and the CLI uses fixed shared OpenSSL.
The wasm-bindgen CLI uses its default rustls TLS feature. Its optional native/vendored OpenSSL
features are not enabled by the installer, so their lock-only sources are not built or loaded.

To update a tool:

1. Verify its version and archive SHA-256 with the official crates.io API and downloaded archive.
2. Extract the verified archive outside this workspace and update its Cargo lock to compatible
   advisory-fixed releases using Rust 1.95.0. For wasm-pack, apply the reviewed source patch first.
3. Copy its lock into `locks/`, preserving registry checksums and the expected local root version.
   Audit every resulting lock against the current RustSec database and review the dependency diff.
4. Run `python3 -m unittest discover -s assets/build_tools -p 'test_*.py'`, install changed tools,
   check their binary versions, and run affected WASM or documentation builds.
5. Keep the wasm-bindgen CLI version synchronized with the application Cargo lock and update
   documentation version references. Review the dated signed APT indexes in `debian.sources` when
   updating the builder's pinned container inputs.
