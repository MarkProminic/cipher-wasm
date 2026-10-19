# cipher-wasm

The certificate engine of the STARTcloud UI's Certificates feature: a Rust crate compiled to WebAssembly that reads, converts, compares, chains and issues certificate and key material inside the browser, so no private key leaves the page.

## What it reads and writes

PEM, DER, PKCS#7, PKCS#8, PKCS#12 with AES-256 and the legacy RC2 and 3DES ciphers, PuTTY PPK v2 and v3, OpenSSH and JWK keys; RSA, EC P-256, EC P-384 and Ed25519.

## What it answers

`detect`, `convert`, `public_key_hash`, `verify_signature`, `build_chain`, `compare`, `generate_key`, `make_csr`, `self_sign` and `sign_csr`, each taking and answering plain JSON values through `wasm-bindgen`; `pkg/cipher_wasm.d.ts` carries the signatures.

## Building

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
wasm-pack build --target web --release --out-dir pkg --out-name cipher_wasm --scope startcloud
```

`pkg/` is the package `@startcloud/cipher-wasm`, build output that is never committed: the release workflow builds it on the runner and uploads it as `cipher-wasm-<version>.tar.gz`, its `package.json` carrying the version `Cargo.toml` carries, and startcloud-ui vendors that tarball under `vendor/cipher-wasm` on the release's dispatch.

## Checks

```bash
cargo fmt --all --check
cargo clippy --target wasm32-unknown-unknown --all-targets -- -D warnings
cargo test --release
```

## License

See [LICENSE.md](LICENSE.md).
