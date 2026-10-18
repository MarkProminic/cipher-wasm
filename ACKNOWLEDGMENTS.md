# Acknowledgments

cipher-wasm is built on many excellent open-source projects. We're grateful to the developers and communities behind them.

## Cryptography

**RustCrypto** — `der`, `spki`, `x509-cert`, `pkcs1`, `pkcs8`, `pkcs5`, `pkcs12`, `cms`, `rsa`, `p256`, `p384`, `ecdsa`, `ssh-key`, `sha1`, `sha2`, `hmac`, `aes`, `des`, `rc2`, `cbc`, `cipher`, `digest`, `const-oid`, `base64ct`, `pem-rfc7468`, `signature`

- Repository: [github.com/RustCrypto](https://github.com/RustCrypto)
- License: MIT OR Apache-2.0

**ed25519-dalek** and **ed25519** — Ed25519 signing and keys

- Repository: [github.com/dalek-cryptography/curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)
- License: BSD-3-Clause

**argon2** — the PPK v3 key derivation

- Repository: [github.com/RustCrypto/password-hashes](https://github.com/RustCrypto/password-hashes)
- License: MIT OR Apache-2.0

**md5** — the legacy fingerprint and PKCS#12 derivation

- License: MIT OR Apache-2.0

## WebAssembly

**wasm-bindgen**, **js-sys** and **serde-wasm-bindgen** — the bridge to the browser

- Repository: [github.com/rustwasm/wasm-bindgen](https://github.com/rustwasm/wasm-bindgen)
- License: MIT OR Apache-2.0

**wasm-pack** — the package build

- Repository: [github.com/rustwasm/wasm-pack](https://github.com/rustwasm/wasm-pack)
- License: MIT OR Apache-2.0

**getrandom** and **rand_core** — the browser's random source

- License: MIT OR Apache-2.0

## Core libraries

- **serde** — serialization (MIT OR Apache-2.0)

## Tooling

- **rustfmt** + **Clippy** — formatting and linting
- **GitHub** — hosting, CI/CD, releases

## Standards

- **Semantic Versioning** — [semver.org](https://semver.org/)

## Disclaimer

This list may not be exhaustive. If you believe a project should be acknowledged here, please open an issue or a pull request. All trademarks are the property of their respective owners.
