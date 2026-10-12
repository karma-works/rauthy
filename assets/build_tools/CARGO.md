# Builder Cargo TLS bootstrap

The official Rust 1.95 binary bundles OpenSSL 3.5.4 inside Cargo. Updating shared libraries cannot
fix that copy. `builder_cargo.py` runs after the fixed OpenSSL installation and replaces the
toolchain's Cargo binary while preserving the rustup dispatch shim and Rust 1.95 compiler.

Source: official crates.io Cargo 0.96.0 archive, SHA-256
`4653299848aaa3c7c34a06a9c1f9248e1340f8d23aa2bd1681a131a070c1cd06`.
The source library version corresponds to Cargo CLI 1.95. `cargo-dependencies.patch` adds the local
package suffix, updates git2/git2-curl/libgit2-sys together, enables git2's explicit credential-helper
feature, and replaces unmaintained im-rc with maintained imbl collections. Small API adaptations
preserve the resolver's Fx hasher and Rc pointer choice and handle git2's new path/URL Result types.
The reviewed lock fixes affected runtime RustSec dependencies and pins libgit2 1.9.7 source through
libgit2-sys 0.18.8. Other Cargo implementation code is unchanged.
Its upstream test-support dependency retains git2 0.20.4 and its two unsoundness notices. That
dev-only version is not compiled or loaded by the installer; Cargo's runtime uses fixed git2 0.21.
Review these notices separately if extending the upstream Cargo test harness.

The CLI identifies itself as `cargo 1.95.0 (rauthy.1 reviewed TLS bootstrap)`. It uses curl HTTP and
vendored-libgit2 features, disables default features, and sets `OPENSSL_NO_VENDOR=1` and
`OPENSSL_DIR=/usr/local`. Its SSL library must report OpenSSL 3.5.9 before installation proceeds.
The old optional openssl-src entry remains in Cargo's all-feature lock; it is not enabled, built,
or loaded. Debian's signed snapshot supplies the shared curl library and its security backports.

The installer uses one compilation job, release optimization level 1, disabled LTO, and 16 codegen
units to bound bootstrap resource use. It checks the compiled CLI and actual TLS version, then
atomically replaces the binary selected by `cargo +1.95.0`. Container root is required; the normal
developer tool bootstrap does not replace a developer's Cargo installation.

When updating, verify the published checksum, review the manifest patch and lock, audit all lock
entries, and run TLS/version and registry/workspace resolution checks using the rebuilt CLI.
Never enable all-static or vendored-openssl: those would embed the old optional C source again.
