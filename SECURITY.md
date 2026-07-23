# Security Policy

Keystead is a zero-knowledge vault: the server never sees plaintext secrets or
vault keys, and this repository holds the Keystead server (the Spring Boot
backend that stores and coordinates opaque encrypted data produced by clients).

## Reporting a vulnerability

Do **not** open a public issue for a security vulnerability. Report it privately
so a fix can be prepared and released before disclosure:

- Open a private security advisory:
  <https://github.com/MidCoard/keystead-server/security/advisories/new>
- Or contact the project owner directly through a private channel.

Please include:

- A description of the issue and its security impact.
- The affected component and, if known, the symbol, route, or migration involved.
- A minimal reproduction or proof of concept.
- Any suggested remediation.

The project owner will acknowledge receipt and coordinate a fix and disclosure
timeline. Vulnerabilities must be reported privately before any public
disclosure.

## Pre-release checklist

Before tagging a release, the server must pass its full CI lane (H2 and
PostgreSQL), the zero-knowledge contract must hold (only opaque ciphertext and
wrapped key packages are stored; no vault key material touches the server), JPA
must be the only database access path, Flyway migrations must be forward-only
and run cleanly on both H2 and PostgreSQL, and no plaintext secret, raw token,
or wrapped vault key may be stored, logged, audited, or returned by any code
path.

## License

This repository is licensed under the Apache License, Version 2.0. Security
fixes and vulnerability reports accepted by the project are contributed and
released under the same license. See [LICENSE](LICENSE) for the full terms.
