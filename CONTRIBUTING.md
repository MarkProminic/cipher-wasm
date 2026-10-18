# Contributing to cipher-wasm

Thank you for your interest in contributing to cipher-wasm! Community contributions are essential to the project's continued growth.

## Important Note on Resources

cipher-wasm is maintained with limited development resources. **Community contributions directly impact the pace of feature development and bug fixes.**

## How to Contribute

### Reporting Issues

Before creating an issue, please:

1. **Search existing issues** to avoid duplicates
2. **Use the appropriate issue template** (bug report, feature request, etc.)
3. **Provide detailed information** — steps to reproduce, expected vs. actual behavior
4. **Include environment details** (browser + version, OS, the startcloud-ui version that carries the engine, the input format)

### Submitting Pull Requests

1. **Fork the repository** and create your feature branch from `main`
2. **Follow the existing code style** — rustfmt + Clippy enforce it (`cargo fmt --all --check`, `cargo clippy --target wasm32-unknown-unknown --all-targets -- -D warnings`)
3. **Keep changes focused** and write clear commit messages using [Conventional Commits](https://www.conventionalcommits.org/) (release-please relies on them)
4. **Fill out the pull request template** completely

### Development Setup

1. Clone your fork of the repository
2. Install the toolchain: `rustup target add wasm32-unknown-unknown` and `cargo install wasm-pack`
3. Build the package: `wasm-pack build --target web --release --out-dir pkg --out-name cipher_wasm --scope startcloud`
4. Point a startcloud-ui checkout at it: its `vendor/cipher-wasm` is this `pkg/`

### Code Style Guidelines

- Follow existing Rust conventions
- **rustfmt** and **Clippy** enforce style — run `cargo fmt --all` and `cargo clippy --target wasm32-unknown-unknown --all-targets -- -D warnings`
- One module per format family (`pem`, `pkcs7`, `pkcs12`, `x509`, `csr`, `keys`, `issue`, `detect`); `lib.rs` holds the wasm-bindgen exports alone
- Every error a caller can see is one plain sentence built with `Error::new`

### What We're Looking For

**High Impact Contributions:**

- Bug fixes (especially a format read wrong or refused)
- New formats and ciphers checked against OpenSSL or PuTTY output
- Performance improvements (package size, conversion time)
- Documentation improvements

**Feature Contributions:**

- New key algorithms and curves
- Better error sentences for refused material

## Response Times and Review Process

Due to limited development resources:

- **Issue responses**: we aim to acknowledge new issues within a few days
- **Pull request reviews**: may take time depending on complexity and workload
- **Documentation updates**: generally reviewed quickly as they're high-impact, low-risk

## Recognition

All contributors are recognized in our [AUTHORS.md](AUTHORS.md) file. We appreciate every contribution, from small fixes to major features!

## Code of Conduct

This project follows our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to abide by its terms.

## License

By contributing to cipher-wasm, you agree that your contributions will be licensed under the [GPL-3.0 License](LICENSE.md).
