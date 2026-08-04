# Keystead Server

Keystead Server is the optional coordination service for Keystead. It stores an
account's opaque encrypted record stream, coordinates approval when a new
device reconstructs a local vault, and hosts optional one-secret share blobs.
It never receives a vault data-encryption key (DEK), local vault passphrase,
biometric data, or plaintext secret.

Keystead has three independently versioned repositories:

| Project | Responsibility |
| --- | --- |
| [Keystead Core](https://github.com/MidCoard/keystead) | Cryptography, vault format, encrypted records, backups, and access-request codecs |
| [Keystead Client](https://github.com/MidCoard/keystead-client) | Local vault files, local login, encryption, sync validation, approval, and restore UI |
| [Keystead Server](https://github.com/MidCoard/keystead-server) | Account sessions, opaque event storage, temporary access-request relay, shares, and audit events |

## Security model

Each account has one personal encrypted record stream. All devices for that
account must use the same DEK to read it. The server stores the vault
fingerprint and encrypted events but cannot prove that ciphertext was produced
by the correct DEK. Every client therefore authenticates downloaded events
locally; unverifiable events are rejected and reported rather than installed.

The server can observe account identifiers, a vault fingerprint, record IDs,
revisions, secret-type protocol values, timestamps, and ciphertext sizes. It
must never receive plaintext fields, the DEK, a local passphrase, biometric
templates, or a private exchange key.

There are no server device identities, device-bound sessions, team vaults,
roles, memberships, invitations, recovery kits, or persistent per-device DEK
packages. The approved restore request temporarily carries one opaque wrapped
DEK package until it expires.
Local biometric login is strictly a client-side convenience for opening an
existing local vault and is unrelated to server authentication.

## Account sessions

`POST /api/v1/users` creates an account. `POST /api/v1/auth/login` exchanges a
username and password for a short-lived bearer token and a rotating opaque
refresh token. Refresh tokens are stored only as SHA-256 hashes.
`POST /api/v1/auth/logout-all` revokes all refresh tokens and increments the
account token version, invalidating already issued access tokens.

Login requests and tokens are account-scoped. They contain no persistent
device identifier.

## Personal record synchronization

- `POST /api/v1/vault/records` appends one opaque encrypted event.
- `GET /api/v1/vault/records?afterSequence=0&limit=100` reads the account's
  stream in server-sequence order.
- `DELETE /api/v1/vault/records/{secretId}` removes every stored event for
  that owner-scoped record ID and returns the number of removed events.
- The first event fixes the one personal vault fingerprint for the account.
- `eventId` provides idempotent retry behavior.
- Ordinary cross-device deletions are authenticated client-created tombstone
  events. Explicit server-copy removal is a separate privacy operation: it
  removes ciphertext history without changing any local vault and records a
  redacted `RECORD_PURGED` audit event.

The server sequence is only a transport cursor. Local record revisions remain
inside the encrypted-record protocol and the client resolves which authentic
revision wins.

## Restore through another device

Restoring through Keystead Server requires another logged-in client that can
already open the same vault:

1. The requesting client signs in to the server and creates a fresh UUID plus
   an ephemeral asymmetric key pair. The private key stays in memory.
2. It posts the UUID, server origin, algorithm, and public key to
   `POST /api/v1/vault-access-requests`.
3. The server returns a canonical request and a human-comparable fingerprint
   bound to the account, UUID, expiry, origin, and public key.
4. An existing client signed into the same account compares the fingerprint,
   opens its local vault, uploads its current encrypted record snapshot, wraps
   the DEK to the request's public key, and approves the request.
5. The requester unwraps the DEK with its memory-only private key, creates a
   new local `.kvault` protected by a newly chosen local passphrase, downloads
   the personal event stream, and installs only records that authenticate.
6. The ephemeral private key is destroyed when the request completes, is
   cancelled, expires, or the client exits.

The server relays one opaque wrapped package. It cannot unwrap or reuse the
DEK, and it does not need to know anything about local biometrics.

## Single-secret shares

The share API hosts a self-contained encrypted `keystead-share:v1` blob behind
a short code. Encryption and passphrase handling happen in the client.

- `POST /api/v1/shares` creates a share.
- `GET /api/v1/shares/{code}` redeems it without an account.
- `GET /api/v1/shares` lists the caller's share metadata.
- `DELETE /api/v1/shares/{code}` removes a caller-owned share.

Burn-after-reading and expiry are enforced by the server. Rate-limited
requests return `429 Too Many Requests` with `Retry-After`.

## Audit trail

The owner-scoped audit API records redacted personal-record writes and login
failures. Audit details reject ciphertext, credential, token, private-key, and
wrapped-key fields. Optional retention and HMAC signing are configured with
`keystead.audit.retention` and `keystead.audit.signing.key`.

## Running locally

The build requires JDK 25 and uses an Adoptium Java 25 toolchain.

```bash
./gradlew bootRun
```

The default profile uses a file-backed H2 database under `data/`. PostgreSQL
can be selected with the included profile and environment variables:

```bash
export KEYSTEAD_DB_URL='jdbc:postgresql://localhost:5432/keystead'
export KEYSTEAD_DB_USERNAME='keystead'
export KEYSTEAD_DB_PASSWORD='replace-this-value'
./gradlew bootRun --args='--spring.profiles.active=postgres'
```

Important settings:

| Setting | Default | Meaning |
| --- | --- | --- |
| `keystead.security.basic-auth-enabled` | `false` | Compatibility-only HTTP Basic authentication |
| `keystead.share.default-ttl` | `P7D` | Default hosted-share lifetime |
| `keystead.share.max-ttl` | `P30D` | Maximum hosted-share lifetime |
| `keystead.audit.retention` | `P365D` | Audit retention period |
| `keystead.audit.signing.key` | empty | Optional base64 HMAC key for audit signing |

For verification run:

```bash
./gradlew spotlessCheck test --no-daemon --rerun-tasks
```

Production deployments still need TLS termination, database backups,
credential management, monitoring, and a durable access-token signing-key
strategy. The current access-token HMAC key is generated at startup, so a
server restart invalidates outstanding access tokens.
