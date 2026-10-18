# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in cipher-wasm, please report it responsibly:

### Preferred Method: Security Advisory

1. Go to the [GitHub Security Advisory page](https://github.com/MarkProminic/cipher-wasm/security/advisories)
2. Click "Report a vulnerability"
3. Fill out the advisory form with detailed information
4. Submit the advisory

### What to Include

- **Description** of the vulnerability
- **Steps to reproduce** the issue
- **Potential impact** of the vulnerability
- **Affected versions** (if known)
- **Suggested fix** (if you have one)

## Response Process

Due to limited development resources, please understand that:

- **Initial Response**: we aim to acknowledge receipt within 48–72 hours
- **Assessment**: initial assessment within about a week
- **Resolution**: timeline depends on severity, typically 1–4 weeks
- **Disclosure**: coordinated disclosure after a fix is available

### Severity Levels

- **Critical**: immediate attention (e.g. XSS enabling account takeover)
- **High**: quick response (authentication / session handling flaws)
- **Medium**: standard timeline
- **Low**: lower priority

## Focus Areas for a Browser Crypto Engine

cipher-wasm is a WebAssembly module that reads, converts and issues certificate and key material inside the browser; nothing it handles leaves the page. The security-relevant areas are:

- **Key material handling** — a private key is decoded, re-encoded and dropped; watch for a key reaching a log, a panic message or an answer that did not ask for it.
- **Parsing of untrusted input** — every format is parsed from bytes a person dropped; a panic or an unbounded allocation on malformed input is a defect.
- **Cryptographic correctness** — a wrong signature check, a weak default cipher or a bad random source; the legacy RC2 and 3DES ciphers are offered only behind the explicit legacy switch.
- **Dependency & supply chain** — vulnerable crates. Dependabot and CodeQL run against this repository.

## Best Practices for Operators

1. **Keep updated** — always run the latest stable release
2. **Serve over HTTPS** — the browser exposes its cryptography only to a secure context
3. **Keep dependencies patched**

## Acknowledgments

We appreciate the security research community's efforts. Responsible disclosure helps protect all users.

### Hall of Fame

Contributors who responsibly report security vulnerabilities will be acknowledged here (with their permission):

- _No vulnerabilities reported yet_

## Updates to This Policy

This security policy may be updated as the project evolves. Check back periodically for changes.
