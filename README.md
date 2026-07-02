# Keystead Server

Keystead Server stores encrypted vault records for authenticated users. It does
not decrypt client secrets; `metadata` and `envelope` are opaque encrypted
payloads from the client/library layer.

## API Surface

- `POST /api/v1/users`
- `POST /api/v1/devices`
- `GET /api/v1/devices`
- `PUT /api/v1/vaults/{vaultId}`
- `GET /api/v1/vaults`
- `PUT /api/v1/vaults/{vaultId}/records/{secretId}`
- `GET /api/v1/vaults/{vaultId}/records/{secretId}`
- `GET /api/v1/vaults/{vaultId}/records?sinceRevision=0`

## Local Development

Run the server:

```powershell
.\gradlew.bat bootRun
```

By default, the server uses a local H2 database file under `data/`. No website
or frontend is included.

Docker support is included for later PostgreSQL setup, but it is optional and
not required for the default backend run:

```powershell
docker compose up -d
.\gradlew.bat bootRun --args='--spring.profiles.active=postgres'
```

To run against PostgreSQL installed directly on your machine instead, set the
database environment variables and enable the `postgres` profile:

```powershell
$env:KEYSTEAD_DB_URL="jdbc:postgresql://localhost:5432/keystead"
$env:KEYSTEAD_DB_USERNAME="keystead"
$env:KEYSTEAD_DB_PASSWORD="your-password"
.\gradlew.bat bootRun --args='--spring.profiles.active=postgres'
```

Run verification:

```powershell
.\gradlew.bat clean build --console=plain
```

The development user is `local` / `local-development-only`. This is only for
local bootstrapping; production auth will replace it.
