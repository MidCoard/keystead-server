# Keystead Server

Keystead Server is the Spring Boot backend for Keystead. It authenticates
users and devices and synchronizes opaque encrypted vault data without
decrypting client secrets.

## What it provides

- User and bearer-token authentication.
- Device enrollment, verification, and revocation.
- Vault and encrypted-record synchronization with revisions and tombstones.
- Wrapped vault-key packages, memberships, and rotation records.
- Redacted, append-only audit events and sync cursors.

The server does not receive plaintext secrets, raw vault keys, or device
private keys. Persistence uses JPA repositories and Flyway migrations.

## Run locally

```powershell
.\gradlew.bat bootRun
```

The default profile uses a local H2 database under `data/`. PostgreSQL is
available through `compose.yml` with the `postgres` profile.

## Verify

```powershell
.\gradlew.bat spotlessCheck test --no-daemon --rerun-tasks
```

Basic authentication is retained only for explicit local compatibility and
test configuration; bearer authentication is the production path.
