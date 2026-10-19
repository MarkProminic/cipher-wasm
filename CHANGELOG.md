# Changelog

## [0.3.0](https://github.com/MarkProminic/cipher-wasm/compare/v0.2.1...v0.3.0) (2026-10-19)


### Features

* Ed448 keys read, written, generated, signed and verified across PKCS[#8](https://github.com/MarkProminic/cipher-wasm/issues/8), SPKI and JWK, RSASSA-PSS as a signature scheme on make_csr, self_sign and sign_csr and verified from the signature's own parameters, the README naming every algorithm ([c574260](https://github.com/MarkProminic/cipher-wasm/commit/c574260ca64ed1e91bac006ec240ec3d3baf6a42))


### Bug Fixes

* the Ed448 private key boxed so the key enum stays small ([be02e14](https://github.com/MarkProminic/cipher-wasm/commit/be02e1472339a8dbc59268e30647696f32cbe4b4))

## [0.2.1](https://github.com/MarkProminic/cipher-wasm/compare/v0.2.0...v0.2.1) (2026-10-19)


### Bug Fixes

* pkg/ built on the release runner and never committed, the tarball the one artifact, release-please no longer bumping pkg/package.json since wasm-pack writes it from Cargo.toml, prettier ignoring target, pkg and the changelog ([782c73d](https://github.com/MarkProminic/cipher-wasm/commit/782c73d1d7046eaa9762818e3fd8352e3ba93fd4))

## [0.2.0](https://github.com/MarkProminic/cipher-wasm/compare/v0.1.0...v0.2.0) (2026-10-19)


### Features

* P-521 and secp256k1 keys beside RSA, P-256, P-384 and Ed25519 in every form the engine reads and writes, PKCS[#8](https://github.com/MarkProminic/cipher-wasm/issues/8), SEC1, SPKI and JWK, P-521 in OpenSSH and PPK too, ECDSA signing by the curve's own digest, SHA-256 for P-256 and secp256k1, SHA-384 for P-384 and SHA-512 for P-521, the certificate facts boxed in the component ([5537087](https://github.com/MarkProminic/cipher-wasm/commit/5537087fb0df7c3d898b361fcf163d8a99808a2e))
* P-521 and secp256k1 keys beside RSA, P-256, P-384 and Ed25519 in every form the engine reads and writes, PKCS[#8](https://github.com/MarkProminic/cipher-wasm/issues/8), SEC1, SPKI and JWK, P-521 in OpenSSH and PPK too, ECDSA signing by the curve's own digest, SHA-256 for P-256 and secp256k1, SHA-384 for P-384 and SHA-512 for P-521, the certificate facts boxed in the component; no zero key or IV anywhere, the PPK derivation held only while a password is given, derived material and random IVs landing in their arrays directly ([d53ae87](https://github.com/MarkProminic/cipher-wasm/commit/d53ae8725d3b7729592400084ac782409fe8b2e8))
* the cipher-wasm engine, wasm-bindgen over RustCrypto detecting, converting, decoding, comparing, chaining and generating PEM, DER, PKCS[#7](https://github.com/MarkProminic/cipher-wasm/issues/7), PKCS[#8](https://github.com/MarkProminic/cipher-wasm/issues/8), PKCS[#12](https://github.com/MarkProminic/cipher-wasm/issues/12) with AES-256 and the legacy RC2 and 3DES ciphers, PPK v2 and v3, OpenSSH and JWK material, with public key hashes, signature checks, CSR, self-signed and CA-signed issuance, built for the web target and checked against OpenSSL and PuTTY fixtures ([9738dc3](https://github.com/MarkProminic/cipher-wasm/commit/9738dc35607789b6f010d1ff47467f1d47d0c47d))
* the engine on the current RustCrypto generation, der 0.8, spki 0.8, x509-cert 0.3, pkcs8 0.11, pkcs5 0.8, pkcs1 0.8, pkcs12 0.2, cms 0.3, rsa 0.10 on crypto-bigint, p256 and p384 0.14, ecdsa 0.17, ed25519-dalek 3, ssh-key 0.7, signature 3, rand_core 0.10, getrandom 0.4, sha1 and sha2 0.11, hmac 0.13, argon2 0.6, aes, des and rc2 0.9, cbc 0.2 and cipher 0.5; certificates issued through the x509-cert builder with a profile carrying the issuer, subject, constraints, key usage, names and copied extensions, names built from a relative distinguished name sequence, randomness from the system source, RSA parts as boxed integers with the CRT exponents derived for JWK, PKCS[#12](https://github.com/MarkProminic/cipher-wasm/issues/12) keeping RC2 and 3DES legacy encryption and PBES2, PPK v2 and v3 and OpenSSH unchanged ([c5e1ef2](https://github.com/MarkProminic/cipher-wasm/commit/c5e1ef21c2a7e087d428cdd2922f174b79158f85))
* the house CI, release-please and dependabot shape, the package tarball and checksums uploaded on each release and startcloud-ui notified, the markdown set and templates, rustfmt applied and the Clippy findings closed ([84b57b0](https://github.com/MarkProminic/cipher-wasm/commit/84b57b0a8411cb658f21bb3bab70dcf50736de16))

## Changelog
