package top.focess.keystead.server.vault;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.server.audit.AuditService;

@Service
class VaultKeyPackageService {

    private final VaultAccessGuard accessGuard;
    private final AuditService audit;
    private final VaultKeyPackageRepository keyPackages;
    private final VaultMemberRepository members;
    private final VaultKeyStateRepository keyStates;
    private final Clock clock;
    private final Validator validator;

    VaultKeyPackageService(
            @NonNull VaultAccessGuard accessGuard,
            @NonNull AuditService audit,
            @NonNull VaultKeyPackageRepository keyPackages,
            @NonNull VaultMemberRepository members,
            @NonNull VaultKeyStateRepository keyStates,
            @NonNull Clock clock,
            @NonNull Validator validator) {
        this.accessGuard = accessGuard;
        this.audit = audit;
        this.keyPackages = keyPackages;
        this.members = members;
        this.keyStates = keyStates;
        this.clock = clock;
        this.validator = validator;
    }

    @Transactional
    void put(
            @NonNull String ownerId,
            @NonNull String fingerprint,
            @NonNull String deviceId,
            @NonNull VaultKeyPackageRequest request) {
        requireVaultAndDevice(ownerId, fingerprint, deviceId);
        validate(request);
        request.validateShape();
        Instant now = clock.instant();
        requireCurrentOrEstablish(ownerId, fingerprint, request.resolvedVaultKeyId(), now);
        store(ownerId, fingerprint, ownerId, deviceId, request, now);
        audit.keyPackageStored(
                ownerId,
                ownerId,
                fingerprint,
                deviceId,
                request.resolvedVaultKeyId(),
                request.keyAlgorithm());
    }

    @Transactional
    void putForRecipient(
            @NonNull String actorId,
            @NonNull String fingerprint,
            @NonNull String recipientId,
            @NonNull String deviceId,
            @NonNull VaultKeyPackageRequest request) {
        accessGuard.requireMemberManager(actorId, fingerprint);
        String ownerId = accessGuard.requireActiveMemberAndResolveOwner(actorId, fingerprint);
        StoredVaultMember member =
                members.find(fingerprint, recipientId)
                        .filter(
                                value ->
                                        value.state() == VaultMemberState.ACCEPTED_PENDING_KEY
                                                || value.state() == VaultMemberState.ACTIVE)
                        .orElseThrow(() -> new VaultNotFoundException("Vault does not exist"));
        if (!keyPackages.verifiedDeviceExists(recipientId, deviceId)) {
            throw new VaultKeyPackageNotFoundException("Device does not exist");
        }
        validate(request);
        request.validateShape();
        Instant now = clock.instant();
        requireCurrent(ownerId, fingerprint, request.resolvedVaultKeyId());
        store(ownerId, fingerprint, recipientId, deviceId, request, now);
        if (member.state() == VaultMemberState.ACCEPTED_PENDING_KEY
                && members.activatePending(fingerprint, recipientId, now) != 1) {
            throw new VaultNotFoundException("Vault does not exist");
        }
        audit.keyPackageStored(
                ownerId,
                actorId,
                fingerprint,
                deviceId,
                request.resolvedVaultKeyId(),
                request.keyAlgorithm());
    }

    @Transactional(readOnly = true)
    @NonNull List<VaultKeyPackageResponse> list(
            @NonNull String actorId, @NonNull String fingerprint) {
        String ownerId = accessGuard.requireActiveMemberAndResolveOwner(actorId, fingerprint);
        List<StoredVaultKeyPackage> packages =
                actorId.equals(ownerId)
                        ? keyPackages.list(ownerId, fingerprint)
                        : keyPackages.listForRecipient(ownerId, fingerprint, actorId);
        return packages.stream().map(VaultKeyPackageResponse::from).toList();
    }

    @Transactional(readOnly = true)
    @NonNull VaultPackageCoverageResponse recipients(
            @NonNull String actorId, @NonNull String fingerprint) {
        accessGuard.requireMemberManager(actorId, fingerprint);
        String ownerId = accessGuard.requireActiveMemberAndResolveOwner(actorId, fingerprint);
        Optional<VaultKeyStateEntity> state =
                keyStates.findById(new VaultEntityId(ownerId, fingerprint));
        String currentVaultKeyId = state.map(value -> value.currentVaultKeyId).orElse(null);
        return new VaultPackageCoverageResponse(
                currentVaultKeyId,
                state.map(value -> value.lifecycleState).orElse(VaultKeyLifecycleState.STABLE),
                state.map(value -> value.lifecycleVersion).orElse(0L),
                keyPackages.listRecipientDevices(ownerId, fingerprint, currentVaultKeyId));
    }

    private void requireCurrentOrEstablish(
            @NonNull String ownerId,
            @NonNull String fingerprint,
            @NonNull String vaultKeyId,
            @NonNull Instant now) {
        VaultEntityId id = new VaultEntityId(ownerId, fingerprint);
        Optional<VaultKeyStateEntity> existing = keyStates.findById(id);
        if (existing.isPresent() && existing.orElseThrow().currentVaultKeyId != null) {
            requireCurrent(existing.orElseThrow(), vaultKeyId);
            return;
        }
        VaultKeyStateEntity state = existing.orElseGet(VaultKeyStateEntity::new);
        state.id = id;
        state.currentVaultKeyId = vaultKeyId;
        state.lifecycleState = VaultKeyLifecycleState.STABLE;
        state.lifecycleVersion = 1L;
        state.pendingGenerationId = null;
        state.updatedAt = now;
        keyStates.saveAndFlush(state);
    }

    private void requireCurrent(
            @NonNull String ownerId, @NonNull String fingerprint, @NonNull String vaultKeyId) {
        VaultKeyStateEntity state =
                keyStates
                        .findById(new VaultEntityId(ownerId, fingerprint))
                        .orElseThrow(
                                () ->
                                        new InvalidVaultKeyPackageRequestException(
                                                "Vault key package uses an unknown vault key id"));
        requireCurrent(state, vaultKeyId);
    }

    private void requireCurrent(@NonNull VaultKeyStateEntity state, @NonNull String vaultKeyId) {
        if (!vaultKeyId.equals(state.currentVaultKeyId)) {
            throw new InvalidVaultKeyPackageRequestException(
                    "Vault key package uses a stale vault key id");
        }
    }

    private void store(
            @NonNull String ownerId,
            @NonNull String fingerprint,
            @NonNull String recipientId,
            @NonNull String deviceId,
            @NonNull VaultKeyPackageRequest request,
            @NonNull Instant now) {
        StoredVaultKeyPackage existing =
                keyPackages.find(ownerId, fingerprint, recipientId, deviceId).orElse(null);
        Instant createdAt = existing == null ? now : existing.createdAt();
        StoredVaultKeyPackage next =
                new StoredVaultKeyPackage(
                        ownerId,
                        fingerprint,
                        recipientId,
                        deviceId,
                        request.resolvedVaultKeyId(),
                        request.keyAlgorithm(),
                        request.encryptedVaultKey(),
                        createdAt,
                        now);
        if (existing == null) {
            keyPackages.insert(next);
        } else {
            keyPackages.update(next);
        }
    }

    private void requireVaultAndDevice(
            @NonNull String ownerId, @NonNull String fingerprint, @NonNull String deviceId) {
        accessGuard.requireOwnedVault(ownerId, fingerprint);
        if (!keyPackages.verifiedDeviceExists(ownerId, deviceId)) {
            throw new VaultKeyPackageNotFoundException("Device does not exist");
        }
    }

    private void validate(@NonNull VaultKeyPackageRequest request) {
        Set<ConstraintViolation<VaultKeyPackageRequest>> violations = validator.validate(request);
        if (!violations.isEmpty()) {
            throw new InvalidVaultKeyPackageRequestException(
                    violations.iterator().next().getPropertyPath() + " is invalid");
        }
    }
}
