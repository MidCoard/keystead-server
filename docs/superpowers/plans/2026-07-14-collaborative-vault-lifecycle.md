# Collaborative Vault Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete invitation, pending-key activation, member/device package coverage, removal, and crash-resumable vault-key rotation across Keystead Core, Server, and Desktop.

**Architecture:** Server owns membership and rotation state but stores only public device/recovery keys and opaque packages. Core exposes a prepared rotation that can wrap the new key before committing the local crash journal and can resume from the initiating device's staged package. Client drives the server target manifest, uploads all packages, commits locally, then atomically commits the server generation.

**Tech Stack:** Java 21/JSpecify/Tink/FileVaultStore, Spring Boot 3.5/JPA/Flyway, Kotlin/JVM/Compose Desktop, JUnit and Kotlin test.

## Global Constraints

- Membership states are exactly `INVITED`, `ACCEPTED_PENDING_KEY`, `ACTIVE`, and `REMOVED`.
- Only `ACTIVE` members read records; role permissions apply only after activation.
- Owners and administrators manage members/packages/rotation; owners cannot be removed or demoted.
- Removing an active member or revoking a packaged device immediately blocks future writes through `ROTATION_REQUIRED`.
- The server never receives plaintext metadata, records, vault keys, recovery secrets, or private keys.
- Server persistence remains JPA-only with Flyway migrations; all public Java APIs use explicit JSpecify annotations.
- A staged generation cannot be canceled or expire after its first package is stored.
- Preserve existing crash-injection coverage and every unrelated local edit/note.
- Commit core and server tasks only; the client directory has no Git metadata and must not be committed.

---

### Task 1: Add collaborative membership and rotation persistence

**Files:**
- Create: `src/main/resources/db/migration/V21__collaborative_vault_lifecycle.sql`
- Modify: `src/main/java/top/focess/keystead/server/vault/VaultMemberState.java`
- Create: `src/main/java/top/focess/keystead/server/vault/VaultKeyLifecycleState.java`
- Create: `src/main/java/top/focess/keystead/server/vault/VaultKeyStateEntity.java`
- Create: `src/main/java/top/focess/keystead/server/vault/VaultKeyStateRepository.java`
- Create: `src/main/java/top/focess/keystead/server/vault/VaultRotationGenerationState.java`
- Create: `src/main/java/top/focess/keystead/server/vault/VaultRotationGenerationEntity.java`
- Create: `src/main/java/top/focess/keystead/server/vault/VaultRotationGenerationRepository.java`
- Create: `src/main/java/top/focess/keystead/server/vault/VaultRotationTargetType.java`
- Create: `src/main/java/top/focess/keystead/server/vault/VaultRotationTargetEntity.java`
- Create: `src/main/java/top/focess/keystead/server/vault/VaultRotationTargetRepository.java`
- Create: `src/main/java/top/focess/keystead/server/vault/VaultRotationPackageEntity.java`
- Create: `src/main/java/top/focess/keystead/server/vault/VaultRotationPackageRepository.java`
- Create: `src/test/java/top/focess/keystead/server/vault/CollaborativeLifecyclePersistenceTest.java`
- Create: `src/test/java/top/focess/keystead/server/vault/CollaborativeLifecycleMigrationTest.java`

**Interfaces:**
- Produces: JPA state for current key/lifecycle version, one pending generation, immutable device/automation/recovery targets, and staged opaque packages.

- [ ] **Step 1: Write failing enum, mapping, migration, and constraint tests**

Test existing `INVITED/ACTIVE/REMOVED` rows survive migration, pending-key persistence, exactly one pending generation per vault, unique target and package ids, positive lifecycle version/generation, valid state checks, package-after-target foreign key, and current key migration from V18 rows.

- [ ] **Step 2: Run focused tests and confirm missing V21/types**

Run: `.\gradlew.bat test --tests '*CollaborativeLifecyclePersistenceTest' --tests '*CollaborativeLifecycleMigrationTest' --console=plain`

Expected: tests fail because V21 and lifecycle entities do not exist.

- [ ] **Step 3: Implement exact schema and enums**

```java
public enum VaultMemberState { INVITED, ACCEPTED_PENDING_KEY, ACTIVE, REMOVED }
public enum VaultKeyLifecycleState { STABLE, ROTATION_REQUIRED, ROTATING }
public enum VaultRotationGenerationState { OPEN, PACKAGING, READY, COMMITTED }
public enum VaultRotationTargetType { DEVICE, AUTOMATION, RECOVERY }
```

Create `vault_key_states(owner_id, vault_id, current_vault_key_id, lifecycle_state, lifecycle_version, pending_generation_id, updated_at)`, `vault_rotation_generations(generation_id, owner_id, vault_id, source_key_id, target_key_id, state, initiator_id, lifecycle_version, created_at, updated_at)`, `vault_rotation_targets(generation_id, target_id, target_type, recipient_id, device_id, principal_id, enrollment_id, recovery_generation, key_algorithm, public_key, required)`, and `vault_rotation_packages(generation_id, target_id, key_algorithm, encrypted_vault_key, created_at)`. Add a check requiring exactly the identity columns appropriate to `DEVICE`, `AUTOMATION`, or `RECOVERY`. Copy V18 current ids into `vault_key_states`, then drop the old table only after the copy.

- [ ] **Step 4: Run persistence tests and formatting**

Run: `.\gradlew.bat spotlessApply test --tests '*CollaborativeLifecyclePersistenceTest' --tests '*CollaborativeLifecycleMigrationTest' --console=plain`

Expected: all pass against migrated and fresh schemas.

- [ ] **Step 5: Commit persistence only**

```powershell
git add -- src/main/resources/db/migration/V21__collaborative_vault_lifecycle.sql src/main/java/top/focess/keystead/server/vault src/test/java/top/focess/keystead/server/vault/CollaborativeLifecyclePersistenceTest.java src/test/java/top/focess/keystead/server/vault/CollaborativeLifecycleMigrationTest.java
git commit -m "Persist collaborative vault lifecycle"
```

### Task 2: Make invitations discoverable and acceptance pending-key aware

**Files:**
- Modify: `src/main/java/top/focess/keystead/server/vault/VaultMemberRepository.java`
- Modify: `src/main/java/top/focess/keystead/server/vault/VaultMemberService.java`
- Modify: `src/main/java/top/focess/keystead/server/vault/VaultMemberController.java`
- Modify: `src/main/java/top/focess/keystead/server/vault/VaultService.java`
- Modify: `src/main/java/top/focess/keystead/server/vault/VaultResponse.java`
- Create: `src/main/java/top/focess/keystead/server/vault/VaultMembershipResponse.java`
- Create: `src/test/java/top/focess/keystead/server/vault/VaultMembershipLifecycleApiTest.java`

**Interfaces:**
- Produces: membership-aware `GET /api/v1/vaults`, `POST .../members/accept`, and `POST .../members/decline`.

- [ ] **Step 1: Write failing discovery and transition tests**

Test owner/active/pending/invited discovery, no unrelated vaults, accept to `ACCEPTED_PENDING_KEY`, no record access while pending, decline to removed, reinvite removed user to invited without restoring packages, repeated identical accept/decline idempotency, and owner protection.

- [ ] **Step 2: Run focused API tests and observe current premature ACTIVE behavior**

Run: `.\gradlew.bat test --tests '*VaultMembershipLifecycleApiTest' --console=plain`

Expected: acceptance assertion fails because current code transitions directly to `ACTIVE`; invitee vault discovery is absent.

- [ ] **Step 3: Implement membership-aware DTO and transitions**

```java
public record VaultMembershipResponse(@NonNull String vaultId, @NonNull String ownerId,
        @NonNull String encryptedMetadata, @NonNull VaultMemberRole role,
        @NonNull VaultMemberState membershipState, @Nullable String currentVaultKeyId,
        @NonNull VaultKeyLifecycleState keyLifecycleState, long lifecycleVersion) {}
```

Join `VaultMemberEntity` with `VaultEntity` and optional key state through JPQL projections/repository entity reads. `accept` changes only `INVITED -> ACCEPTED_PENDING_KEY`; `decline` changes invited/pending to removed. `VaultAccessGuard` continues to accept only `ACTIVE` for record operations.

- [ ] **Step 4: Run membership and existing vault tests**

Run: `.\gradlew.bat spotlessApply test --tests '*VaultMembershipLifecycleApiTest' --tests '*VaultApiTest' --tests '*VaultKeyPackageApiTest' --console=plain`

Expected: all pass after updating existing acceptance expectations to pending-key semantics.

- [ ] **Step 5: Commit membership lifecycle**

```powershell
git add -- src/main/java/top/focess/keystead/server/vault src/test/java/top/focess/keystead/server/vault
git commit -m "Add pending key membership lifecycle"
```

### Task 3: Expose authorized recipient devices and activate on first package

**Files:**
- Create: `src/main/java/top/focess/keystead/server/vault/VaultPackageRecipientDeviceResponse.java`
- Create: `src/main/java/top/focess/keystead/server/vault/VaultPackageCoverageResponse.java`
- Modify: `src/main/java/top/focess/keystead/server/vault/VaultKeyPackageController.java`
- Modify: `src/main/java/top/focess/keystead/server/vault/VaultKeyPackageService.java`
- Modify: `src/main/java/top/focess/keystead/server/vault/VaultKeyPackageRepository.java`
- Modify: `src/main/java/top/focess/keystead/server/vault/VaultMemberRepository.java`
- Modify: `src/main/java/top/focess/keystead/server/vault/VaultKeyStateRepository.java`
- Create: `src/test/java/top/focess/keystead/server/vault/VaultPackageCoverageApiTest.java`

**Interfaces:**
- Produces: manager-only `GET /api/v1/vaults/{vaultId}/package-recipients`, current-device coverage, and atomic first-package activation.

- [ ] **Step 1: Write failing privacy, eligibility, coverage, and activation tests**

Test owner/admin access, editor/viewer/outsider denial, accepted/active devices only, verified/non-revoked/wrapping-capable filtering, no unrelated device exposure, per-device covered flag, stale key rejection, first current package activating pending user, and rollback leaving pending state when package insert fails.

- [ ] **Step 2: Run focused test and confirm missing endpoint/pending recipient rejection**

Run: `.\gradlew.bat test --tests '*VaultPackageCoverageApiTest' --console=plain`

Expected: 404 for recipient view and current package service rejects a pending recipient.

- [ ] **Step 3: Implement response and transactional activation**

```java
public record VaultPackageRecipientDeviceResponse(@NonNull String userId,
        @NonNull VaultMemberRole role, @NonNull VaultMemberState memberState,
        @NonNull String deviceId, @NonNull String keyAlgorithm,
        @NonNull String publicKey, boolean covered) {}
```

Allow package publication to `ACCEPTED_PENDING_KEY` or `ACTIVE`; validate the device belongs to that recipient and is eligible. Establish the initial current key id in `vault_key_states` on the first owner package. Insert/update the opaque package and change pending membership to active in the same transaction only when the package key id equals current.

- [ ] **Step 4: Run package/member tests**

Run: `.\gradlew.bat spotlessApply test --tests '*VaultPackageCoverageApiTest' --tests '*VaultKeyPackageApiTest' --tests '*VaultMember*Test' --console=plain`

Expected: all pass.

- [ ] **Step 5: Commit coverage and activation**

```powershell
git add -- src/main/java/top/focess/keystead/server/vault src/test/java/top/focess/keystead/server/vault
git commit -m "Activate members through device packages"
```

### Task 4: Require rotation after member removal or packaged-device revocation

**Files:**
- Create: `src/main/java/top/focess/keystead/server/vault/VaultLifecycleConflictException.java`
- Create: `src/main/java/top/focess/keystead/server/vault/VaultDeviceRevocationService.java`
- Create: `src/main/java/top/focess/keystead/server/vault/VaultAutomationRevocationService.java`
- Modify: `src/main/java/top/focess/keystead/server/vault/VaultMemberService.java`
- Modify: `src/main/java/top/focess/keystead/server/vault/VaultKeyPackageRepository.java`
- Modify: `src/main/java/top/focess/keystead/server/vault/VaultKeyStateRepository.java`
- Modify: `src/main/java/top/focess/keystead/server/identity/IdentityService.java`
- Modify: `src/main/java/top/focess/keystead/server/automation/AutomationService.java`
- Modify: `src/main/java/top/focess/keystead/server/record/EncryptedRecordService.java`
- Modify: `src/main/java/top/focess/keystead/server/audit/AuditEventType.java`
- Modify: `src/main/java/top/focess/keystead/server/audit/AuditService.java`
- Create: `src/test/java/top/focess/keystead/server/vault/VaultRemovalRotationApiTest.java`

**Interfaces:**
- Produces: immediate access revocation, package invalidation, `ROTATION_REQUIRED`, and distinct 409 write rejection.

- [ ] **Step 1: Write failing removal/revocation/write-blocking tests**

Test active removal, pending removal with/without historical package, removed package read denial, reads by remaining active users, writes blocked for all roles, packaged-device revocation marking every affected vault, unpackaged-device revocation not marking vaults, packaged-automation revocation marking its vault, role change not rotating, and redacted audit fields.

- [ ] **Step 2: Run focused test and observe current writes remain allowed**

Run: `.\gradlew.bat test --tests '*VaultRemovalRotationApiTest' --console=plain`

Expected: lifecycle/write assertions fail under current behavior.

- [ ] **Step 3: Implement state transition and write guard**

```java
public void requireStableForWrite(@NonNull String ownerId, @NonNull String vaultId) {
    VaultKeyLifecycleState state = keyStates.find(ownerId, vaultId)
            .map(StoredVaultKeyState::lifecycleState).orElse(VaultKeyLifecycleState.STABLE);
    if (state != VaultKeyLifecycleState.STABLE) {
        throw new VaultLifecycleConflictException(state);
    }
}
```

Call the guard after writable-member authorization and before record validation/storage. Member removal updates state and invalidates removed-recipient package rows in one transaction. Device revocation asks `VaultDeviceRevocationService` for distinct current-package vaults before revoking, then marks those states required in the same outer transaction. Automation revocation performs the equivalent lookup through `VaultAutomationRevocationService` before invalidating the principal.

- [ ] **Step 4: Run removal, record, and device tests**

Run: `.\gradlew.bat spotlessApply test --tests '*VaultRemovalRotationApiTest' --tests '*EncryptedRecord*Test' --tests '*UserDeviceApiTest' --console=plain`

Expected: all pass.

- [ ] **Step 5: Commit mandatory rotation behavior**

```powershell
git add -- src/main/java/top/focess/keystead/server/vault src/main/java/top/focess/keystead/server/identity src/main/java/top/focess/keystead/server/record src/main/java/top/focess/keystead/server/audit src/test/java/top/focess/keystead/server/vault
git commit -m "Require rotation after access revocation"
```

### Task 5: Implement server-side staged rotation manifests and commit

**Files:**
- Replace: `src/main/java/top/focess/keystead/server/vault/VaultKeyRotationService.java`
- Modify: `src/main/java/top/focess/keystead/server/vault/VaultKeyRotationController.java`
- Create: `src/main/java/top/focess/keystead/server/vault/VaultRotationBeginRequest.java`
- Create: `src/main/java/top/focess/keystead/server/vault/VaultRotationResponse.java`
- Create: `src/main/java/top/focess/keystead/server/vault/VaultRotationTargetResponse.java`
- Create: `src/main/java/top/focess/keystead/server/vault/VaultRotationPackageRequest.java`
- Modify: `src/main/java/top/focess/keystead/server/vault/VaultKeyPackageRepository.java`
- Create: `src/main/java/top/focess/keystead/server/automation/AutomationRotationBridge.java`
- Modify: `src/main/java/top/focess/keystead/server/automation/AutomationPrincipalRepository.java`
- Modify: `src/main/java/top/focess/keystead/server/automation/AutomationVaultKeyPackageRepository.java`
- Create: `src/main/java/top/focess/keystead/server/recovery/RecoveryRotationBridge.java`
- Modify: `src/main/java/top/focess/keystead/server/recovery/RecoveryEnrollmentRepository.java`
- Modify: `src/main/java/top/focess/keystead/server/recovery/RecoveryVaultPackageRepository.java`
- Create: `src/test/java/top/focess/keystead/server/vault/StagedVaultRotationApiTest.java`

**Interfaces:**
- Produces: begin/status/package/self-package/cancel-before-upload/commit endpoints under `/api/v1/vaults/{vaultId}/rotations`.

- [ ] **Step 1: Write failing manifest, race, coverage, and resume tests**

Test owner/admin begin, editor denial, expected-current/lifecycle-version conflict, exact active-device targets, selected pending members, active automation targets, recovery targets, one pending generation, new device excluded after snapshot, member/automation removal invalidating targets, package metadata binding, incomplete commit, ready commit, old package replacement, pending activation, self staged-package retrieval only, cancel before first upload, no cancel/expiry after upload, idempotent retry, and two concurrent commit callers with one winner.

- [ ] **Step 2: Run focused test and confirm old one-step endpoint fails expectations**

Run: `.\gradlew.bat test --tests '*StagedVaultRotationApiTest' --console=plain`

Expected: tests fail because only the legacy one-step key-id declaration exists.

- [ ] **Step 3: Implement exact staged service API**

```java
@Transactional
public @NonNull VaultRotationResponse begin(@NonNull String actorId,
        @NonNull String vaultId, @NonNull VaultRotationBeginRequest request);

@Transactional
public @NonNull VaultRotationResponse putPackage(@NonNull String actorId,
        @NonNull String vaultId, @NonNull String generationId,
        @NonNull String targetId, @NonNull VaultRotationPackageRequest request);

@Transactional
public @NonNull VaultRotationResponse commit(@NonNull String actorId,
        @NonNull String vaultId, @NonNull String generationId);
```

Snapshot device targets with vault-package repository JPA queries. `AutomationRotationBridge` and `RecoveryRotationBridge` expose immutable public-key target records and accept committed opaque packages while keeping their package-private repositories inside their owning packages. Generate target UUIDs server-side. Validate request key id/algorithm/ciphertext bounds and all public binding fields; ciphertext remains opaque. On commit require one package for every required current target, lock/compare lifecycle version, invoke the bridges to replace current automation/recovery packages, replace device packages, activate selected pending members, set new current id and `STABLE`, clear pending id, increment version, and audit public ids only.

- [ ] **Step 4: Run staged rotation and existing package tests**

Run: `.\gradlew.bat spotlessApply test --tests '*StagedVaultRotationApiTest' --tests '*VaultKeyPackageApiTest' --tests '*RecoveryEnrollmentApiTest' --console=plain`

Expected: all pass.

- [ ] **Step 5: Commit staged server rotation**

```powershell
git add -- src/main/java/top/focess/keystead/server/vault src/main/java/top/focess/keystead/server/recovery src/test/java/top/focess/keystead/server/vault
git commit -m "Stage resumable vault key rotations"
```

### Task 6: Add a prepared and resumable core rotation API

**Files:**
- Create: `D:/IdeaProjects/keystead/keystead-core/src/main/java/top/focess/keystead/service/PreparedVaultKeyRotation.java`
- Modify: `D:/IdeaProjects/keystead/keystead-core/src/main/java/top/focess/keystead/service/VaultHandle.java`
- Modify: `D:/IdeaProjects/keystead/keystead-core/src/main/java/top/focess/keystead/service/DefaultVaultHandle.java`
- Modify: `D:/IdeaProjects/keystead/keystead-core/src/main/java/top/focess/keystead/service/DefaultVaultService.java`
- Create: `D:/IdeaProjects/keystead/keystead-core/src/test/java/top/focess/keystead/service/PreparedVaultKeyRotationTest.java`
- Modify: `D:/IdeaProjects/keystead/keystead-core/src/test/java/top/focess/keystead/store/FileVaultStoreTest.java`

**Interfaces:**
- Produces: prepare new key, wrap packages before local commit, resume from staged self package, and commit through the existing journal.

- [ ] **Step 1: Write failing state/secret/crash tests**

Test fresh key id, package wrapping before commit, original handle mutation blocked after prepare, commit with matching self package, mismatch rejection, close without commit preserving old vault, resume from staged package/private key/context, old/new handle closure, secret-free `toString()`, and existing journal crash boundaries for prepared rotation.

- [ ] **Step 2: Run focused core tests and confirm missing API**

Run from `D:\IdeaProjects\keystead`: `.\gradlew.bat :keystead-core:test --tests '*PreparedVaultKeyRotationTest' --tests '*FileVaultStoreTest' --console=plain`

Expected: compilation fails because `PreparedVaultKeyRotation` is absent.

- [ ] **Step 3: Implement exact public API with JSpecify annotations**

```java
public interface PreparedVaultKeyRotation extends AutoCloseable {
    @NonNull VaultId vaultId();
    @NonNull KeyId sourceVaultKeyId();
    @NonNull KeyId targetVaultKeyId();
    @NonNull DeviceVaultKeyPackage wrapVaultKeyPackageForDevice(
            byte @NonNull [] publicKey, byte @NonNull [] context);
    @NonNull VaultHandle commitWithDevicePackage(@NonNull DeviceVaultKeyPackage localPackage);
    boolean isCommitted();
    @Override void close();
}

public interface VaultHandle extends AutoCloseable {
    @NonNull PreparedVaultKeyRotation prepareVaultKeyRotation();
    @NonNull PreparedVaultKeyRotation resumeVaultKeyRotation(
            @NonNull DeviceVaultKeyPackage stagedPackage,
            byte @NonNull [] devicePrivateKey, byte @NonNull [] context);
}
```

The prepared object owns the target `VaultKey`, precomputes re-encrypted active records without mutating the store, and records SHA-256 fingerprints of every package it generates. `commitWithDevicePackage` accepts only a generated package fingerprint, or the exact staged package used to construct a resumed rotation, preventing a same-key-id/wrong-ciphertext header. It commits one `VaultKeyRotation` whose header wraps the target key with that initiating-device package. `close()` wipes target key/records and leaves the source authoritative unless committed. Existing password rotation delegates to the same internal commit path with a master-password header.

- [ ] **Step 4: Run formatting, prepared rotation, crash tests, and nullness tests**

Run: `.\gradlew.bat :keystead-core:spotlessApply :keystead-core:test --tests '*PreparedVaultKeyRotationTest' --tests '*FileVaultStoreTest' --tests top.focess.keystead.NullnessSemanticsTest --console=plain`

Expected: all pass, including 48 or more `FileVaultStoreTest` cases.

- [ ] **Step 5: Commit core prepared rotation only**

```powershell
git add -- keystead-core/src/main/java/top/focess/keystead/service keystead-core/src/test/java/top/focess/keystead/service/PreparedVaultKeyRotationTest.java keystead-core/src/test/java/top/focess/keystead/store/FileVaultStoreTest.java
git commit -m "Prepare resumable vault key rotations"
```

### Task 7: Add client collaboration and rotation protocol models

**Files:**
- Modify: `D:/IdeaProjects/keystead-client/src/main/kotlin/top/focess/keystead/client/KeysteadServerClient.kt`
- Create: `D:/IdeaProjects/keystead-client/src/main/kotlin/top/focess/keystead/client/CollaborationModels.kt`
- Create: `D:/IdeaProjects/keystead-client/src/main/kotlin/top/focess/keystead/client/VaultRotationClient.kt`
- Modify: `D:/IdeaProjects/keystead-client/src/test/kotlin/top/focess/keystead/client/KeysteadServerClientTest.kt`
- Create: `D:/IdeaProjects/keystead-client/src/test/kotlin/top/focess/keystead/client/VaultRotationClientTest.kt`

**Interfaces:**
- Produces: membership/invitation/member/recipient/coverage DTOs and all staged rotation HTTP methods.

- [ ] **Step 1: Write failing strict serialization and error tests**

Test list memberships, accept/decline, list/change/remove members, recipient devices, begin/status/upload/self-package/cancel/commit, URL encoding, unknown JSON field rejection, nullable current key, lifecycle conflict details, and ciphertext-free exception text.

- [ ] **Step 2: Run focused client tests and confirm missing models/methods**

Run from `D:\IdeaProjects\keystead-client`: `.\gradlew.bat test --tests '*KeysteadServerClientTest' --tests '*VaultRotationClientTest' --console=plain`

Expected: compilation fails on the new methods/types.

- [ ] **Step 3: Implement immutable client models and methods**

```kotlin
enum class ServerVaultMemberState { INVITED, ACCEPTED_PENDING_KEY, ACTIVE, REMOVED }
enum class ServerVaultKeyLifecycleState { STABLE, ROTATION_REQUIRED, ROTATING }
data class ServerVaultMembership(
    val vaultId: String, val ownerId: String, val encryptedMetadata: String,
    val role: String, val membershipState: ServerVaultMemberState,
    val currentVaultKeyId: String?, val keyLifecycleState: ServerVaultKeyLifecycleState,
    val lifecycleVersion: Long,
)
```

Use Gson's parsed tree with explicit allowed-field sets as current lifecycle code does. Never serialize package bytes into exception messages.

- [ ] **Step 4: Run client protocol tests**

Run: `.\gradlew.bat test --tests '*KeysteadServerClientTest' --tests '*VaultRotationClientTest' --console=plain`

Expected: all pass.

### Task 8: Drive package coverage and resumable rotation from LocalVaultSession

**Files:**
- Modify: `D:/IdeaProjects/keystead-client/src/main/kotlin/top/focess/keystead/client/LocalVaultSession.kt`
- Create: `D:/IdeaProjects/keystead-client/src/main/kotlin/top/focess/keystead/client/CollaborativeVaultService.kt`
- Create: `D:/IdeaProjects/keystead-client/src/main/kotlin/top/focess/keystead/client/VaultRotationWorkflow.kt`
- Create: `D:/IdeaProjects/keystead-client/src/main/kotlin/top/focess/keystead/client/VaultRotationStateStore.kt`
- Modify: `D:/IdeaProjects/keystead-client/src/test/kotlin/top/focess/keystead/client/LocalVaultSessionTest.kt`
- Create: `D:/IdeaProjects/keystead-client/src/test/kotlin/top/focess/keystead/client/CollaborativeVaultServiceTest.kt`
- Create: `D:/IdeaProjects/keystead-client/src/test/kotlin/top/focess/keystead/client/VaultRotationWorkflowTest.kt`

**Interfaces:**
- Produces: publish uncovered recipient packages, activate accepted members, begin/resume rotation, upload exact target packages, local commit, server commit, and restart state.

- [ ] **Step 1: Write failing multi-user/device and interruption tests**

Test filtering approved algorithms, target-specific package context, all required devices, active automation and recovery targets, first-package activation, no current-user-only assumption, interruption before uploads, after partial upload, after all uploads/before local commit, after local commit/before server commit, self staged-package resume, stale generation, and no raw key in `VaultRotationStateStore`.

- [ ] **Step 2: Run focused workflow tests and observe current self-device-only publication**

Run: `.\gradlew.bat test --tests '*CollaborativeVaultServiceTest' --tests '*VaultRotationWorkflowTest' --tests '*LocalVaultSessionTest' --console=plain`

Expected: new tests fail; current code lists only the signed-in user's devices and performs local rotation before server staging.

- [ ] **Step 3: Implement exact orchestration order**

```kotlin
class VaultRotationWorkflow(
    private val client: KeysteadServerClient,
    private val stateStore: VaultRotationStateStore,
) {
    fun rotate(session: LocalVaultSession, identity: LocalDeviceIdentity,
        selectedPendingUsers: Set<String> = emptySet()): ServerVaultRotation
    fun resume(session: LocalVaultSession, identity: LocalDeviceIdentity): ServerVaultRotation
}
```

Call server begin, `handle.prepareVaultKeyRotation`, wrap/upload every target using its exact context, verify `READY`, commit locally with the initiating device package, persist only generation/key ids/stage, then commit server. On restart fetch the current device's staged package and call core resume. Remove the old `rotateVaultKeyAndPublish` order after its tests are replaced.

- [ ] **Step 4: Run collaboration/session tests**

Run: `.\gradlew.bat test --tests '*CollaborativeVaultServiceTest' --tests '*VaultRotationWorkflowTest' --tests '*LocalVaultSessionTest' --console=plain`

Expected: all pass.

- [ ] **Step 5: Confirm the client remains uncommitted**

Run: `Test-Path -LiteralPath D:\IdeaProjects\keystead-client\.git`

Expected: `False`; report files but do not commit.

### Task 9: Add end-user collaboration UI and lifecycle end-to-end tests

**Files:**
- Create: `D:/IdeaProjects/keystead-client/src/main/kotlin/top/focess/keystead/client/CollaborationViewModel.kt`
- Create: `D:/IdeaProjects/keystead-client/src/test/kotlin/top/focess/keystead/client/CollaborationViewModelTest.kt`
- Modify: `D:/IdeaProjects/keystead-client/src/main/kotlin/top/focess/keystead/client/Main.kt`
- Modify: `D:/IdeaProjects/keystead-client/README.md`
- Create: `src/test/java/top/focess/keystead/server/vault/CollaborativeVaultEndToEndTest.java`
- Modify: `README.md`

**Interfaces:**
- Produces: invitation, waiting-for-key, member/role/device coverage, removal, mandatory-rotation, progress/resume, and completion UI.

- [ ] **Step 1: Write failing view-model and two-user end-to-end tests**

View-model tests cover every state and no secret-bearing `toString()`. End-to-end tests create owner/member devices, invite, accept pending, publish package, open shared vault through core, enforce viewer/editor/admin roles, package a new device, remove member, reject future writes, rotate remaining targets, reject removed access, and resume both sides of local commit.

- [ ] **Step 2: Run focused tests and confirm missing UI/fixture**

Run client: `.\gradlew.bat test --tests '*CollaborationViewModelTest' --console=plain`

Run server: `.\gradlew.bat test --tests '*CollaborativeVaultEndToEndTest' --console=plain`

Expected: tests fail before the view model and complete lifecycle fixture exist.

- [ ] **Step 3: Implement Compose panels and honest documentation**

```kotlin
sealed interface CollaborationUiState {
    data object Loading : CollaborationUiState
    data class Invitations(val values: List<ServerVaultMembership>) : CollaborationUiState
    data class WaitingForKey(val vaultId: String) : CollaborationUiState
    data class Managing(val vaultId: String, val members: List<ServerVaultMember>,
        val devices: List<ServerVaultRecipientDevice>) : CollaborationUiState
    data class Rotating(val vaultId: String, val completed: Int, val required: Int,
        val resumable: Boolean) : CollaborationUiState
}
```

Show why writes are blocked, which devices lack packages, and that removal protects future versions only after rotation. Remove README language claiming the collaborative lifecycle is absent once end-to-end tests pass; do not add product comparisons or external-audit claims.

- [ ] **Step 4: Run complete verification and extract XML counts**

Run core from `D:\IdeaProjects\keystead`: `.\gradlew.bat test --console=plain`

Run server: `.\gradlew.bat test --console=plain`

Run client from `D:\IdeaProjects\keystead-client`: `.\gradlew.bat test packageDistributionForCurrentOS --console=plain`

Expected: all commands exit 0. Sum every `build/test-results/**/TEST-*.xml` and report tests/failures/errors/skips for each repository; do not claim other operating-system native integration tests ran unless executed on those hosts.

- [ ] **Step 5: Commit server end-to-end and documentation changes**

```powershell
git add -- README.md src/test/java/top/focess/keystead/server/vault/CollaborativeVaultEndToEndTest.java
git commit -m "Complete collaborative vault lifecycle"
```

Core commits are made in Task 6. Do not commit the client repository.
