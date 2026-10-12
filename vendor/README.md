# Security compatibility patches

These copies retain their published package versions and upstream licenses. They are local patches,
not new upstream releases. Remove each override once a compatible upstream release contains its fix.

## h2 0.3.27

Base: the crates.io `h2` 0.3.27 archive, SHA-256
`0beca50380b1fc32983fc1cb4587bfa4bb9e78fc259aad4a0032d2080309222d`.

Backport of [upstream commit 193833e][h2-patch], released in h2 0.4.16, addressing
[RUSTSEC-2026-0258][h2-advisory]. Actix still depends on h2 0.3; substituting h2 0.4 would change
its HTTP type/API compatibility. The backport bounds DATA framing overhead per connection, discards
nonfinal empty DATA, and returns buffering credit when the application consumes a small DATA frame.
Adaptations retain the 0.3 decoder's padding handling, config field, and buffer-cleanup signatures.

The upstream budget unit tests are retained. `tests/data_frame_budget.rs` reproduces the upstream
empty, padded-empty, and small-frame regression cases using a raw in-memory peer, without pulling in
the upstream test harness. It also checks that an empty END_STREAM still completes a body. The
published examples and their unused TLS dev dependencies are not included as build targets.

Run `cargo +1.95.0 test --manifest-path vendor/h2/Cargo.toml --lib proto::streams` and
`cargo +1.95.0 test --manifest-path vendor/h2/Cargo.toml --test data_frame_budget`.
The full published crate unit suite also expects an external HPACK fixture corpus excluded from
its crates.io archive; those unchanged fixture tests are outside the security-backport checks.
Version-only scanners may still flag 0.3.27; inspect this local patch rather than suppressing the
advisory for unpatched registry copies. Client examples override h2 explicitly because Cargo only
honors patches in the root manifest of each build.

## atrium-common 0.1.4

Base: the crates.io `atrium-common` 0.1.4 archive, SHA-256
`98466259d2e6189ddf3439b96432d5303668b4d51c2a78996934d981065550f3`.
Its MIT license is copied from upstream commit `1762e5bcf00fb2a038fa4a94777acdd9cb6d4b70`.
Its wasm-only `lru` dependency minimum changes from
0.16.3 to 0.18.2, which fixes [RUSTSEC-2026-0253][lru-advisory]. The cache APIs remain unchanged;
native targets continue using moka. No library source is changed.

## openssl-sys 0.9.117

Base: the crates.io `openssl-sys` 0.9.117 archive, SHA-256
`b47e7e6bb2c38cd930d25a23b40fa52e068c10e85f3e03a7f5ba5aaca5713695`.
Its MIT license and all Rust/build sources are retained unchanged. Only the `openssl-src`
requirement in both manifests changes from `300.2.0` to `=400.0.2`. The existing bindings already
support OpenSSL 4; the published vendored requirement still selects OpenSSL 3.6.3.

The root lock pins the unchanged official `openssl-src` 400.0.2+4.0.3 archive, SHA-256
`d2093956673b8dbda85c87fa4fb78e70698ce6c5978a2837d1613f661d3bef76`.
Its bundled `VERSION.dat` identifies OpenSSL 4.0.3, released 29 September 2026. This
[security release][openssl-release] fixes relative CRL distribution point memory exhaustion
(CVE-2026-35189), concurrent X.509 extension cache use-after-free (CVE-2026-84783), and the other
current OpenSSL fixes. No OpenSSL C source is copied here, changed, or fetched by this local patch.
Cargo fetches the checksum-pinned registry source before the existing vendored build runs.

OpenSSL 4 strengthens strict certificate/CRL checks and removes some deprecated APIs. Validate
RSA/PKCS8 signing and FIDO metadata verification, including the official signed BLOB, after updates.
Remove this override when upstream's vendored requirement selects a fixed OpenSSL release.

[h2-patch]: https://github.com/hyperium/h2/commit/193833e87c639e39751f339a9c375a44c8bfab54
[h2-advisory]: https://rustsec.org/advisories/RUSTSEC-2026-0258.html
[lru-advisory]: https://rustsec.org/advisories/RUSTSEC-2026-0253.html
[openssl-release]: https://github.com/openssl/openssl/releases/tag/openssl-4.0.3
