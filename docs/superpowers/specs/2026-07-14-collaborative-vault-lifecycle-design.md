# Collaborative Vault Lifecycle Design

## Purpose

Keystead collaboration must make membership, device-key coverage, and vault-key
rotation one coherent lifecycle. Authorization remains server-enforced, while
all vault-key encryption, decryption, and rewrapping remain client-side. The
server stores roles, public device material, lifecycle state, and opaque key
packages; it never receives an unwrapped vault key or plaintext vault content.

The design completes invitation discovery, acceptance, member administration,
per-device package publication, removal, and rotation recovery across the server
and desktop client. Persistence remains JPA-only with Flyway migrations.

## Membership model

Membership has four states:

- `INVITED`: a manager has invited the user. The recipient may see and respond
  to the invitation but has no record or key-package access.
- `ACCEPTED_PENDING_KEY`: the recipient accepted and may expose eligible public
  device keys to vault managers, but no current vault-key package exists yet.
- `ACTIVE`: at least one verified, non-revoked recipient device has a package for
  the current vault-key identifier. Normal role-based access is enabled.
- `REMOVED`: record, metadata, recipient-device, and package access is revoked.

The owner membership is always `ACTIVE`. An owner cannot be removed or demoted,
and ownership transfer is outside this lifecycle. Reinviting a removed member
creates a new invitation transition and never silently restores old packages.

Roles remain `OWNER`, `ADMIN`, `EDITOR`, and `VIEWER`. Owners and administrators
manage invitations, roles, package publication, removals, and rotation. Editors
write records; viewers read records. Only `ACTIVE` members receive record access.
An accepted member waiting for a package can see the vault identifier, encrypted
display metadata required by the client, its role, and package-coverage status,
but not encrypted records.

Acceptance and the first valid current-generation device package are separate
transactions. Publishing the first package atomically activates the member.
Additional verified devices remain individually pending until a manager publishes
packages for them; membership activity never implies that every device is
covered.

## Discovery and management APIs

Authenticated vault discovery returns every membership relevant to the caller,
including invitations and pending-key memberships. Each summary contains the
vault identifier, owner identifier, caller role, membership state, current
vault-key identifier, vault rotation state, and opaque encrypted metadata. A
compatibility endpoint may continue to return only accessible vaults, but the
desktop client uses the membership-aware view.

Recipients accept or decline only their own invitations. Decline transitions to
`REMOVED` without requiring rotation because no key package was issued.

An owner or administrator may request a package-recipient view scoped to one
vault. It returns accepted or active members and their verified, non-revoked,
wrapping-capable devices: device identifier, wrapping algorithm and public key,
verification state, and coverage for the current or pending rotation generation.
It never exposes private material, authentication tokens, unrelated devices, or
devices belonging to invited/removed users.

Member and package responses use immutable DTOs with explicit JSpecify nullness
annotations. Enumeration and authorization errors use the server's existing
problem-response conventions and do not disclose unrelated users or vaults.

## Vault-key lifecycle

A vault has one of three key lifecycle states:

- `STABLE`: ordinary record reads and permitted writes use the committed key.
- `ROTATION_REQUIRED`: reads remain available to active members, but writes are
  blocked until a removal-triggered rotation excludes the removed principal.
- `ROTATING`: one staged rotation generation is collecting device and recovery
  packages; ordinary writes remain blocked.

Removing an `ACTIVE` member immediately revokes API access, invalidates their
server-side package availability, and changes the vault to
`ROTATION_REQUIRED`. This cannot revoke ciphertext or keys already copied by the
member; rotation protects future versions. Removing an invited or
`ACCEPTED_PENDING_KEY` member requires rotation only if a package was ever
committed for that member.

Role changes do not rotate keys. A downgrade takes effect immediately for server
authorization. Revoking a device marks every vault for which that device has a
current package as `ROTATION_REQUIRED`, even when the member has another device;
this excludes a lost or compromised device from future versions. Revoking a
device that never received a current package requires no vault rotation.

## Staged, resumable rotation

Owners and administrators may begin rotation when a vault is `STABLE` or
`ROTATION_REQUIRED`. Begin uses optimistic checks on the current key identifier
and vault lifecycle version, creates exactly one pending generation, and
snapshots required targets:

- every verified, non-revoked, wrapping-capable device of each `ACTIVE` member;
- selected `ACCEPTED_PENDING_KEY` members that the initiator wants to activate;
  and
- every active recovery enrollment that should retain access.

An active member with no eligible device contributes no device target and is
reported as uncovered. A newly enrolled device after the snapshot is packaged
separately after commit. Concurrent membership removal invalidates or revises the
pending generation before it can commit; a removed principal is never carried
into a new committed generation.

The client performs rotation in this order:

1. Begin or resume the pending server generation.
2. Generate the new vault key and all target packages in client memory.
3. Upload opaque staged packages, including the initiating device's package.
4. Verify server coverage against the exact target manifest.
5. Commit local vault re-encryption through the crash-recoverable core rotation
   journal.
6. Commit the server generation atomically.
7. Resume normal synchronization under the new key identifier.

Uploading the initiating device package before local re-encryption makes an
interruption recoverable. Before server commit, the initiator may retrieve its
own staged package and resume opening the locally rotated vault. Staged packages
are never served as ordinary committed packages to other devices.

Server commit succeeds only when every required target has one valid package
bound to the pending vault, key identifier, recipient/enrollment, device where
applicable, algorithm, and rotation generation. Commit atomically changes the
current key identifier, publishes staged packages, activates included pending
members, clears the removal requirement, increments the lifecycle version, and
records a redacted audit event.

Before the first staged package is accepted, the initiator may cancel because no
durable client can depend on the generation. After any package is uploaded, the
generation cannot be canceled or automatically expired: a client may already
have committed local rotation. An eligible target device retrieves only its own
staged package, opens the same pending key, and can resume missing uploads and
commit. Replacing an unrecoverable pending generation is a separate destructive
administrative recovery operation and is not part of this lifecycle.

Old-generation packages cannot satisfy new coverage. A stale begin, upload,
membership revision, or commit receives a conflict response containing public
lifecycle identifiers only.

## Server persistence

Flyway migrations extend membership state and add persisted vault-key lifecycle,
rotation generation, immutable target manifest, and staged package state. JPA
entities and repositories are the only application persistence mechanism.

Database constraints enforce one owner membership per vault, one live membership
per user and vault, one pending rotation per vault, unique targets within a
generation, unique packages per target, and monotonic lifecycle versions. Service
transactions lock or compare versions at invitation acceptance, first-package
activation, removal, rotation begin, target revision, and rotation commit.

Opaque ciphertext remains bounded by existing request and column limits. Audit
records identify actor, vault, affected user/device, transition, and public key
identifiers, but never include package bytes, vault metadata plaintext, tokens,
or key material.

## Desktop client workflow

The server client adds immutable models and methods for membership-aware vault
listing, invitation response, member listing, role changes, removal, eligible
recipient devices, package coverage, rotation begin/resume/upload/commit, and
rotation status.

The desktop interface provides:

- a pending-invitations section with accept and decline actions;
- a vault member view for roles, membership state, device coverage, and removal;
- a publish-keys action that packages the current key for uncovered eligible
  devices without exposing it to the server;
- a removal flow that clearly requires rotation before future writes; and
- a rotation/resume flow showing target coverage and the exact stage reached.

Accepting an invitation ends in a visible waiting-for-key state. Activation is
reported only after the client can fetch and decrypt a package for its current
device. UI state and logs contain identifiers and progress only. Vault keys and
decrypted packages stay in bounded session objects and are wiped on close where
possible.

The client never assumes an `ACTIVE` membership means its current device is
covered. It checks device-specific package availability and presents an action
for a manager to publish the missing package.

## Error and concurrency handling

All lifecycle commands are idempotent where a repeated identical request is
safe. Conflicting repeats return the committed or current public state. The
server rejects self-removal by an owner, cross-vault devices, revoked devices,
unverified devices, stale key identifiers, wrong algorithms, duplicate targets,
incomplete manifests, and unauthorized member or rotation operations.

Reads remain possible during required or active rotation for members who already
possess the committed key. Writes are rejected with a distinct rotation-required
or rotation-in-progress problem type so clients do not retry them as generic
transport failures.

## Verification

Server unit and integration tests cover every state and role transition,
membership-aware discovery, invitation privacy, first-package activation,
device-level coverage, removal and immediate authorization loss, write blocking,
target snapshots, concurrent removal/rotation, stale generations, incomplete
coverage, idempotency, transaction rollback, redacted audits, and JPA constraints.

Core tests cover package binding and malformed input plus crash recovery before
and after each local rotation journal durability boundary. Existing
`FileVaultStoreTest` crash-injection coverage remains mandatory.

Client tests cover API serialization, invitation and member state, authorized
target selection, package generation for multiple users and devices, activation,
removal, staged rotation, restart/resume through the initiating device package,
and absence of secrets from diagnostics.

End-to-end lifecycle tests use two users and multiple devices to prove:

1. invitation, acceptance, package publication, and shared-vault opening;
2. role enforcement for read, write, and member management;
3. new-device package publication for an active member;
4. removal followed by mandatory rotation and future-data exclusion; and
5. recovery from interruption before and after local rotation but before server
   commit.
