package top.focess.keystead.server.vault;

import jakarta.validation.Validator;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.server.audit.AuditService;
import top.focess.keystead.server.automation.AutomationRotationBridge;
import top.focess.keystead.server.recovery.RecoveryRotationBridge;

@Service
public class VaultKeyRotationService {

    private final VaultAccessGuard accessGuard;
    private final VaultKeyStateRepository keyStates;
    private final VaultMemberRepository members;
    private final VaultKeyPackageRepository keyPackages;
    private final VaultRotationGenerationRepository generations;
    private final VaultRotationTargetRepository targets;
    private final VaultRotationPackageRepository rotationPackages;
    private final AutomationRotationBridge automationRotations;
    private final RecoveryRotationBridge recoveryRotations;
    private final AuditService audit;
    private final Clock clock;
    private final Validator validator;

    VaultKeyRotationService(
            @NonNull VaultAccessGuard accessGuard,
            @NonNull VaultKeyStateRepository keyStates,
            @NonNull VaultMemberRepository members,
            @NonNull VaultKeyPackageRepository keyPackages,
            @NonNull VaultRotationGenerationRepository generations,
            @NonNull VaultRotationTargetRepository targets,
            @NonNull VaultRotationPackageRepository rotationPackages,
            @NonNull AutomationRotationBridge automationRotations,
            @NonNull RecoveryRotationBridge recoveryRotations,
            @NonNull AuditService audit,
            @NonNull Clock clock,
            @NonNull Validator validator) {
        this.accessGuard = accessGuard;
        this.keyStates = keyStates;
        this.members = members;
        this.keyPackages = keyPackages;
        this.generations = generations;
        this.targets = targets;
        this.rotationPackages = rotationPackages;
        this.automationRotations = automationRotations;
        this.recoveryRotations = recoveryRotations;
        this.audit = audit;
        this.clock = clock;
        this.validator = validator;
    }

    @Transactional
    void rotate(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull VaultKeyRotationRequest request) {
        accessGuard.requireOwnedVault(ownerId, vaultId);
        if (!validator.validate(request).isEmpty()) {
            throw new IllegalArgumentException("vaultKeyId is invalid");
        }
        VaultEntityId id = new VaultEntityId(ownerId, vaultId);
        Optional<VaultKeyStateEntity> existing = keyStates.findById(id);
        existing.filter(state -> state.lifecycleState != VaultKeyLifecycleState.STABLE)
                .ifPresent(
                        state -> {
                            throw new VaultLifecycleConflictException(state.lifecycleState);
                        });
        VaultKeyStateEntity state = existing.orElseGet(VaultKeyStateEntity::new);
        state.id = id;
        state.currentVaultKeyId = request.vaultKeyId();
        state.lifecycleState = VaultKeyLifecycleState.STABLE;
        state.lifecycleVersion = existing.isPresent() ? state.lifecycleVersion + 1L : 1L;
        state.pendingGenerationId = null;
        state.updatedAt = clock.instant();
        keyStates.save(state);
    }

    public void requireCurrentOrLegacy(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String vaultKeyId) {
        keyStates
                .findById(new VaultEntityId(ownerId, vaultId))
                .map(state -> state.currentVaultKeyId)
                .filter(currentVaultKeyId -> !currentVaultKeyId.equals(vaultKeyId))
                .ifPresent(
                        value -> {
                            throw new InvalidVaultKeyPackageRequestException(
                                    "Vault key package uses a stale vault key id");
                        });
    }

    @Transactional
    @NonNull VaultRotationResponse begin(
            @NonNull String actorId,
            @NonNull String vaultId,
            @NonNull VaultRotationBeginRequest request) {
        accessGuard.requireMemberManager(actorId, vaultId);
        String ownerId = accessGuard.requireActiveMemberAndResolveOwner(actorId, vaultId);
        validate(request);
        if (request.expectedCurrentVaultKeyId().equals(request.targetVaultKeyId())) {
            throw new InvalidVaultRotationRequestException(
                    "Rotation target key id must differ from the current key id");
        }
        VaultKeyStateEntity current =
                keyStates
                        .findById(new VaultEntityId(ownerId, vaultId))
                        .orElseThrow(
                                () ->
                                        new VaultRotationConflictException(
                                                "Vault does not have a current key"));
        if (!request.expectedCurrentVaultKeyId().equals(current.currentVaultKeyId)
                || request.expectedLifecycleVersion() != current.lifecycleVersion
                || current.lifecycleState == VaultKeyLifecycleState.ROTATING
                || current.pendingGenerationId != null) {
            throw new VaultRotationConflictException("Vault key lifecycle changed");
        }
        requireSelectedPendingMembers(vaultId, request.selectedPendingUsers());
        Instant now = clock.instant();
        String generationId = UUID.randomUUID().toString();
        VaultRotationGenerationEntity generation = new VaultRotationGenerationEntity();
        generation.generationId = generationId;
        generation.ownerId = ownerId;
        generation.vaultId = vaultId;
        generation.sourceKeyId = current.currentVaultKeyId;
        generation.targetKeyId = request.targetVaultKeyId();
        generation.state = VaultRotationGenerationState.OPEN;
        generation.initiatorId = actorId;
        generation.lifecycleVersion = current.lifecycleVersion + 1L;
        generation.priorLifecycleState = current.lifecycleState;
        generation.pendingMarker = "P";
        generation.createdAt = now;
        generation.updatedAt = now;
        generations.saveAndFlush(generation);
        if (keyStates.beginRotation(
                        ownerId,
                        vaultId,
                        request.expectedCurrentVaultKeyId(),
                        request.expectedLifecycleVersion(),
                        generationId,
                        now)
                != 1) {
            throw new VaultRotationConflictException("Vault key lifecycle changed");
        }
        List<VaultRotationTargetEntity> manifest = new java.util.ArrayList<>();
        manifest.addAll(
                deviceTargets(
                        ownerId,
                        vaultId,
                        current.currentVaultKeyId,
                        request.selectedPendingUsers(),
                        generationId));
        automationRotations
                .targets(ownerId, vaultId, current.currentVaultKeyId)
                .forEach(value -> manifest.add(automationTarget(generationId, value)));
        recoveryRotations
                .targets(ownerId, vaultId, current.currentVaultKeyId)
                .forEach(value -> manifest.add(recoveryTarget(generationId, ownerId, value)));
        if (manifest.stream()
                .noneMatch(target -> target.targetType == VaultRotationTargetType.DEVICE)) {
            throw new VaultRotationConflictException("Rotation has no recoverable device target");
        }
        targets.saveAllAndFlush(manifest);
        return response(generation);
    }

    @Transactional
    @NonNull VaultRotationResponse status(
            @NonNull String actorId, @NonNull String vaultId, @NonNull String generationId) {
        String ownerId = accessGuard.requireActiveMemberAndResolveOwner(actorId, vaultId);
        VaultRotationGenerationEntity generation =
                requireGeneration(ownerId, vaultId, generationId);
        pruneInvalidTargets(generation);
        return response(generation);
    }

    @Transactional
    @NonNull VaultRotationResponse putPackage(
            @NonNull String actorId,
            @NonNull String vaultId,
            @NonNull String generationId,
            @NonNull String targetId,
            @NonNull VaultRotationPackageRequest request) {
        String ownerId = accessGuard.requireActiveMemberAndResolveOwner(actorId, vaultId);
        VaultRotationGenerationEntity generation =
                requireGeneration(ownerId, vaultId, generationId);
        if (generation.state == VaultRotationGenerationState.COMMITTED) {
            return response(generation);
        }
        pruneInvalidTargets(generation);
        validate(request);
        VaultRotationTargetEntity target =
                targets.findById(new VaultRotationTargetEntity.Key(generationId, targetId))
                        .orElseThrow(
                                () -> new VaultNotFoundException("Rotation target does not exist"));
        requireBinding(generation, target, request);
        VaultRotationPackageEntity.Key id =
                new VaultRotationPackageEntity.Key(generationId, targetId);
        VaultRotationPackageEntity existing = rotationPackages.findById(id).orElse(null);
        if (existing != null) {
            if (!existing.keyAlgorithm.equals(request.keyAlgorithm())
                    || !existing.encryptedVaultKey.equals(request.encryptedVaultKey())) {
                throw new VaultRotationConflictException("Rotation target already has a package");
            }
            return response(generation);
        }
        VaultRotationPackageEntity keyPackage = new VaultRotationPackageEntity();
        keyPackage.generationId = generationId;
        keyPackage.targetId = targetId;
        keyPackage.keyAlgorithm = request.keyAlgorithm();
        keyPackage.encryptedVaultKey = request.encryptedVaultKey();
        keyPackage.createdAt = clock.instant();
        rotationPackages.saveAndFlush(keyPackage);
        generation.state =
                rotationPackages.countByGenerationId(generationId)
                                == targets.countByGenerationId(generationId)
                        ? VaultRotationGenerationState.READY
                        : VaultRotationGenerationState.PACKAGING;
        generation.updatedAt = clock.instant();
        generations.saveAndFlush(generation);
        return response(generation);
    }

    @Transactional
    @NonNull VaultRotationPackageResponse selfPackage(
            @NonNull String actorId,
            @NonNull String vaultId,
            @NonNull String generationId,
            @NonNull String deviceId) {
        String ownerId = accessGuard.requireActiveMemberAndResolveOwner(actorId, vaultId);
        VaultRotationGenerationEntity generation =
                requireGeneration(ownerId, vaultId, generationId);
        if (generation.state == VaultRotationGenerationState.COMMITTED) {
            throw new VaultNotFoundException("Rotation package does not exist");
        }
        pruneInvalidTargets(generation);
        VaultRotationTargetEntity target =
                targets.findByGenerationIdOrderByTargetId(generationId).stream()
                        .filter(value -> value.targetType == VaultRotationTargetType.DEVICE)
                        .filter(value -> actorId.equals(value.recipientId))
                        .filter(value -> deviceId.equals(value.deviceId))
                        .findFirst()
                        .orElseThrow(
                                () ->
                                        new VaultNotFoundException(
                                                "Rotation package does not exist"));
        VaultRotationPackageEntity keyPackage =
                rotationPackages
                        .findById(new VaultRotationPackageEntity.Key(generationId, target.targetId))
                        .orElseThrow(
                                () ->
                                        new VaultNotFoundException(
                                                "Rotation package does not exist"));
        return new VaultRotationPackageResponse(
                target.targetId,
                generation.targetKeyId,
                keyPackage.keyAlgorithm,
                keyPackage.encryptedVaultKey);
    }

    @Transactional
    void cancel(@NonNull String actorId, @NonNull String vaultId, @NonNull String generationId) {
        accessGuard.requireMemberManager(actorId, vaultId);
        String ownerId = accessGuard.requireActiveMemberAndResolveOwner(actorId, vaultId);
        VaultRotationGenerationEntity generation =
                requireGeneration(ownerId, vaultId, generationId);
        if (generation.state == VaultRotationGenerationState.COMMITTED
                || rotationPackages.countByGenerationId(generationId) != 0) {
            throw new VaultRotationConflictException("Rotation can no longer be canceled");
        }
        Instant now = clock.instant();
        if (keyStates.cancelRotation(
                        ownerId,
                        vaultId,
                        generationId,
                        generation.lifecycleVersion,
                        generation.priorLifecycleState,
                        now)
                != 1) {
            throw new VaultRotationConflictException("Vault key lifecycle changed");
        }
        targets.deleteForGeneration(generationId);
        generations.delete(generation);
        generations.flush();
    }

    @Transactional
    @NonNull VaultRotationResponse commit(
            @NonNull String actorId, @NonNull String vaultId, @NonNull String generationId) {
        String ownerId = accessGuard.requireActiveMemberAndResolveOwner(actorId, vaultId);
        VaultRotationGenerationEntity generation =
                requireGeneration(ownerId, vaultId, generationId);
        if (generation.state == VaultRotationGenerationState.COMMITTED) {
            return response(generation);
        }
        pruneInvalidTargets(generation);
        long targetCount = targets.countByGenerationId(generationId);
        if (generation.state != VaultRotationGenerationState.READY
                || targetCount == 0
                || rotationPackages.countByGenerationId(generationId) != targetCount) {
            throw new VaultRotationConflictException("Rotation package coverage is incomplete");
        }
        List<VaultRotationTargetEntity> manifest =
                targets.findByGenerationIdOrderByTargetId(generationId);
        Map<String, VaultRotationPackageEntity> packages = new HashMap<>();
        rotationPackages
                .findByGenerationIdOrderByTargetId(generationId)
                .forEach(value -> packages.put(value.targetId, value));
        Instant now = clock.instant();
        if (keyStates.commitRotation(
                        ownerId,
                        vaultId,
                        generationId,
                        generation.lifecycleVersion,
                        generation.targetKeyId,
                        now)
                != 1) {
            throw new VaultRotationConflictException("Vault key lifecycle changed");
        }
        keyPackages.deleteForVault(ownerId, vaultId);
        List<AutomationRotationBridge.Package> automationPackages = new java.util.ArrayList<>();
        List<RecoveryRotationBridge.Package> recoveryPackages = new java.util.ArrayList<>();
        for (VaultRotationTargetEntity target : manifest) {
            VaultRotationPackageEntity keyPackage = packages.get(target.targetId);
            switch (target.targetType) {
                case DEVICE -> {
                    keyPackages.insert(
                            new StoredVaultKeyPackage(
                                    ownerId,
                                    vaultId,
                                    Objects.requireNonNull(target.recipientId),
                                    Objects.requireNonNull(target.deviceId),
                                    generation.targetKeyId,
                                    keyPackage.keyAlgorithm,
                                    keyPackage.encryptedVaultKey,
                                    now,
                                    now));
                    members.activatePending(
                            vaultId, Objects.requireNonNull(target.recipientId), now);
                }
                case AUTOMATION ->
                        automationPackages.add(
                                new AutomationRotationBridge.Package(
                                        Objects.requireNonNull(target.principalId),
                                        keyPackage.keyAlgorithm,
                                        keyPackage.encryptedVaultKey));
                case RECOVERY ->
                        recoveryPackages.add(
                                new RecoveryRotationBridge.Package(
                                        Objects.requireNonNull(target.enrollmentId),
                                        Objects.requireNonNull(target.recoveryGeneration),
                                        keyPackage.keyAlgorithm,
                                        keyPackage.encryptedVaultKey));
            }
        }
        automationRotations.replace(
                ownerId, vaultId, generation.targetKeyId, automationPackages, now);
        recoveryRotations.replace(ownerId, vaultId, generation.targetKeyId, recoveryPackages, now);
        generation.state = VaultRotationGenerationState.COMMITTED;
        generation.lifecycleVersion++;
        generation.pendingMarker = null;
        generation.updatedAt = now;
        generations.saveAndFlush(generation);
        audit.vaultRotationCommitted(
                ownerId,
                actorId,
                vaultId,
                generationId,
                Objects.requireNonNull(generation.sourceKeyId),
                generation.targetKeyId,
                targetCount);
        return response(generation);
    }

    private @NonNull List<VaultRotationTargetEntity> deviceTargets(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull String currentVaultKeyId,
            @NonNull Set<String> selectedPendingUsers,
            @NonNull String generationId) {
        return keyPackages.listRecipientDevices(ownerId, vaultId, currentVaultKeyId).stream()
                .filter(
                        value ->
                                value.memberState() == VaultMemberState.ACTIVE
                                        || selectedPendingUsers.contains(value.userId()))
                .map(value -> deviceTarget(generationId, value))
                .toList();
    }

    private static @NonNull VaultRotationTargetEntity deviceTarget(
            @NonNull String generationId, @NonNull VaultPackageRecipientDeviceResponse value) {
        VaultRotationTargetEntity target = new VaultRotationTargetEntity();
        target.generationId = generationId;
        target.targetId = UUID.randomUUID().toString();
        target.targetType = VaultRotationTargetType.DEVICE;
        target.recipientId = value.userId();
        target.deviceId = value.deviceId();
        target.keyAlgorithm = value.keyAlgorithm();
        target.publicKey = value.publicKey();
        target.required = true;
        return target;
    }

    private static @NonNull VaultRotationTargetEntity automationTarget(
            @NonNull String generationId, AutomationRotationBridge.@NonNull Target value) {
        VaultRotationTargetEntity target = new VaultRotationTargetEntity();
        target.generationId = generationId;
        target.targetId = UUID.randomUUID().toString();
        target.targetType = VaultRotationTargetType.AUTOMATION;
        target.principalId = value.principalId();
        target.keyAlgorithm = value.keyAlgorithm();
        target.publicKey = value.publicKey();
        target.required = true;
        return target;
    }

    private static @NonNull VaultRotationTargetEntity recoveryTarget(
            @NonNull String generationId,
            @NonNull String ownerId,
            RecoveryRotationBridge.@NonNull Target value) {
        VaultRotationTargetEntity target = new VaultRotationTargetEntity();
        target.generationId = generationId;
        target.targetId = UUID.randomUUID().toString();
        target.targetType = VaultRotationTargetType.RECOVERY;
        target.recipientId = ownerId;
        target.enrollmentId = value.enrollmentId();
        target.recoveryGeneration = value.generation();
        target.keyAlgorithm = value.keyAlgorithm();
        target.publicKey = value.publicKey();
        target.required = true;
        return target;
    }

    private void pruneInvalidTargets(@NonNull VaultRotationGenerationEntity generation) {
        if (generation.state == VaultRotationGenerationState.COMMITTED) {
            return;
        }
        String sourceKeyId = Objects.requireNonNull(generation.sourceKeyId);
        Set<String> validDevices = new HashSet<>();
        keyPackages
                .listRecipientDevices(generation.ownerId, generation.vaultId, sourceKeyId)
                .forEach(value -> validDevices.add(value.userId() + "\u0000" + value.deviceId()));
        Set<String> validAutomations = new HashSet<>();
        automationRotations
                .targets(generation.ownerId, generation.vaultId, sourceKeyId)
                .forEach(value -> validAutomations.add(value.principalId()));
        Set<String> validRecoveries = new HashSet<>();
        recoveryRotations
                .targets(generation.ownerId, generation.vaultId, sourceKeyId)
                .forEach(
                        value ->
                                validRecoveries.add(
                                        value.enrollmentId() + "\u0000" + value.generation()));
        boolean changed = false;
        for (VaultRotationTargetEntity target :
                targets.findByGenerationIdOrderByTargetId(generation.generationId)) {
            boolean valid =
                    switch (target.targetType) {
                        case DEVICE ->
                                validDevices.contains(
                                        target.recipientId + "\u0000" + target.deviceId);
                        case AUTOMATION -> validAutomations.contains(target.principalId);
                        case RECOVERY ->
                                validRecoveries.contains(
                                        target.enrollmentId + "\u0000" + target.recoveryGeneration);
                    };
            if (!valid) {
                rotationPackages.deleteForTarget(generation.generationId, target.targetId);
                targets.deleteById(
                        new VaultRotationTargetEntity.Key(
                                generation.generationId, target.targetId));
                changed = true;
            }
        }
        if (changed) {
            rotationPackages.flush();
            targets.flush();
            long targetCount = targets.countByGenerationId(generation.generationId);
            long packageCount = rotationPackages.countByGenerationId(generation.generationId);
            generation.state =
                    targetCount > 0 && packageCount == targetCount
                            ? VaultRotationGenerationState.READY
                            : packageCount == 0
                                    ? VaultRotationGenerationState.OPEN
                                    : VaultRotationGenerationState.PACKAGING;
            generation.updatedAt = clock.instant();
            generations.saveAndFlush(generation);
        }
    }

    private void requireSelectedPendingMembers(
            @NonNull String vaultId, @NonNull Set<String> selectedPendingUsers) {
        for (String userId : selectedPendingUsers) {
            StoredVaultMember member =
                    members.find(vaultId, userId)
                            .orElseThrow(
                                    () ->
                                            new InvalidVaultRotationRequestException(
                                                    "Selected pending member is invalid"));
            if (member.state() != VaultMemberState.ACCEPTED_PENDING_KEY) {
                throw new InvalidVaultRotationRequestException(
                        "Selected pending member is invalid");
            }
        }
    }

    private @NonNull VaultRotationGenerationEntity requireGeneration(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String generationId) {
        return generations
                .findByGenerationIdAndOwnerIdAndVaultId(generationId, ownerId, vaultId)
                .orElseThrow(() -> new VaultNotFoundException("Rotation does not exist"));
    }

    private void requireBinding(
            @NonNull VaultRotationGenerationEntity generation,
            @NonNull VaultRotationTargetEntity target,
            @NonNull VaultRotationPackageRequest request) {
        if (!generation.targetKeyId.equals(request.vaultKeyId())
                || target.targetType != request.targetType()
                || !Objects.equals(target.recipientId, request.recipientId())
                || !Objects.equals(target.deviceId, request.deviceId())
                || !Objects.equals(target.principalId, request.principalId())
                || !Objects.equals(target.enrollmentId, request.enrollmentId())
                || !Objects.equals(target.recoveryGeneration, request.recoveryGeneration())
                || !target.keyAlgorithm.equals(request.keyAlgorithm())) {
            throw new InvalidVaultRotationRequestException(
                    "Rotation package does not match its target binding");
        }
    }

    private @NonNull VaultRotationResponse response(
            @NonNull VaultRotationGenerationEntity generation) {
        Set<String> covered = new HashSet<>();
        rotationPackages
                .findByGenerationIdOrderByTargetId(generation.generationId)
                .forEach(value -> covered.add(value.targetId));
        List<VaultRotationTargetResponse> targetResponses =
                targets.findByGenerationIdOrderByTargetId(generation.generationId).stream()
                        .map(value -> targetResponse(value, covered.contains(value.targetId)))
                        .toList();
        return new VaultRotationResponse(
                generation.generationId,
                generation.vaultId,
                Objects.requireNonNull(generation.sourceKeyId),
                generation.targetKeyId,
                generation.state,
                generation.lifecycleVersion,
                targetResponses);
    }

    private static @NonNull VaultRotationTargetResponse targetResponse(
            @NonNull VaultRotationTargetEntity target, boolean covered) {
        return new VaultRotationTargetResponse(
                target.targetId,
                target.targetType,
                target.recipientId,
                target.deviceId,
                target.principalId,
                target.enrollmentId,
                target.recoveryGeneration,
                target.keyAlgorithm,
                target.publicKey,
                target.required,
                covered);
    }

    private void validate(@NonNull Object request) {
        if (!validator.validate(request).isEmpty()) {
            throw new InvalidVaultRotationRequestException("Vault rotation request is invalid");
        }
    }
}
