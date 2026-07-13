package top.focess.keystead.server.recovery;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.server.audit.AuditService;
import top.focess.keystead.server.crypto.ServerCryptoAlgorithmRegistry;
import top.focess.keystead.server.vault.VaultAccessGuard;
import top.focess.keystead.server.vault.VaultKeyRotationService;

@Service
class RecoveryEnrollmentService {

    private final RecoveryEnrollmentRepository enrollments;
    private final RecoveryVaultPackageRepository vaultPackages;
    private final PasswordEncoder passwordEncoder;
    private final VaultAccessGuard vaultAccess;
    private final VaultKeyRotationService rotations;
    private final AuditService audit;
    private final Validator validator;
    private final Clock clock;

    RecoveryEnrollmentService(
            @NonNull RecoveryEnrollmentRepository enrollments,
            @NonNull RecoveryVaultPackageRepository vaultPackages,
            @NonNull PasswordEncoder passwordEncoder,
            @NonNull VaultAccessGuard vaultAccess,
            @NonNull VaultKeyRotationService rotations,
            @NonNull AuditService audit,
            @NonNull Validator validator,
            @NonNull Clock clock) {
        this.enrollments = enrollments;
        this.vaultPackages = vaultPackages;
        this.passwordEncoder = passwordEncoder;
        this.vaultAccess = vaultAccess;
        this.rotations = rotations;
        this.audit = audit;
        this.validator = validator;
        this.clock = clock;
    }

    @Transactional
    @NonNull RecoveryEnrollmentResponse create(
            @NonNull String username, @NonNull RecoveryEnrollmentRequest request) {
        validate(request);
        requireRecoveryAlgorithm(request.wrappingAlgorithm());
        if (enrollments.findPending(username).isPresent()) {
            throw new RecoveryConflictException("A recovery enrollment is already pending");
        }
        @Nullable Long maximum = enrollments.maximumGeneration(username);
        if (maximum != null && request.generation() <= maximum) {
            throw new RecoveryConflictException("Recovery generation must increase");
        }

        Instant now = clock.instant();
        RecoveryEnrollmentEntity entity = new RecoveryEnrollmentEntity();
        entity.id =
                new RecoveryEnrollmentId(
                        username, UUID.randomUUID().toString(), request.generation());
        entity.credentialHash = passwordEncoder.encode(request.accountCredential());
        entity.wrappingAlgorithm = request.wrappingAlgorithm();
        entity.wrappingPublicKey = request.wrappingPublicKey();
        entity.encryptedPrivateKey = request.encryptedPrivateKey();
        entity.state = RecoveryEnrollmentState.PENDING;
        entity.lifecycleMarker = "P";
        entity.createdAt = now;
        RecoveryEnrollmentEntity saved = enrollments.saveAndFlush(entity);
        audit.recoveryEnrollmentCreated(username, saved.id.enrollmentId, saved.id.generation);
        return RecoveryEnrollmentResponse.from(saved);
    }

    @Transactional(readOnly = true)
    @NonNull List<RecoveryEnrollmentResponse> list(@NonNull String username) {
        return enrollments.listCurrent(username).stream()
                .map(RecoveryEnrollmentResponse::from)
                .toList();
    }

    @Transactional
    @NonNull RecoveryEnrollmentResponse commit(
            @NonNull String username,
            @NonNull String enrollmentId,
            @NonNull RecoveryEnrollmentCommitRequest request) {
        validate(request);
        RecoveryEnrollmentEntity pending =
                enrollments
                        .findById(
                                new RecoveryEnrollmentId(
                                        username, enrollmentId, request.generation()))
                        .orElseThrow(
                                () ->
                                        new RecoveryNotFoundException(
                                                "Recovery enrollment does not exist"));
        if (pending.state == RecoveryEnrollmentState.ACTIVE) {
            return RecoveryEnrollmentResponse.from(pending);
        }
        if (pending.state != RecoveryEnrollmentState.PENDING) {
            throw new RecoveryConflictException("Recovery enrollment is not pending");
        }

        Instant now = clock.instant();
        @Nullable RecoveryEnrollmentEntity active = enrollments.findActive(username).orElse(null);
        if (active != null) {
            active.state = RecoveryEnrollmentState.SUPERSEDED;
            active.lifecycleMarker = null;
            active.consumedAt = now;
            enrollments.saveAndFlush(active);
        }
        pending.state = RecoveryEnrollmentState.ACTIVE;
        pending.lifecycleMarker = "A";
        pending.committedAt = now;
        RecoveryEnrollmentEntity saved = enrollments.saveAndFlush(pending);
        audit.recoveryEnrollmentCommitted(username, enrollmentId, request.generation());
        return RecoveryEnrollmentResponse.from(saved);
    }

    @Transactional
    @NonNull RecoveryVaultPackageResponse putPackage(
            @NonNull String actorId,
            @NonNull String username,
            @NonNull String enrollmentId,
            @NonNull String vaultId,
            @NonNull RecoveryVaultPackageRequest request) {
        vaultAccess.requireMemberManager(actorId, vaultId);
        String ownerId = vaultAccess.requireActiveMemberAndResolveOwner(actorId, vaultId);
        vaultAccess.requireActiveMember(username, vaultId);
        validate(request);
        requireRecoveryAlgorithm(request.keyAlgorithm());
        RecoveryEnrollmentEntity enrollment =
                enrollments
                        .findById(
                                new RecoveryEnrollmentId(
                                        username, enrollmentId, request.generation()))
                        .filter(
                                value ->
                                        value.state == RecoveryEnrollmentState.PENDING
                                                || value.state == RecoveryEnrollmentState.ACTIVE)
                        .orElseThrow(
                                () ->
                                        new RecoveryNotFoundException(
                                                "Recovery enrollment does not exist"));
        rotations.requireCurrentOrLegacy(ownerId, vaultId, request.vaultKeyId());

        RecoveryVaultPackageId id =
                new RecoveryVaultPackageId(
                        username, enrollment.id.enrollmentId, enrollment.id.generation, vaultId);
        Instant now = clock.instant();
        @Nullable RecoveryVaultPackageEntity existing = vaultPackages.findById(id).orElse(null);
        RecoveryVaultPackageEntity entity = new RecoveryVaultPackageEntity();
        entity.id = id;
        entity.vaultKeyId = request.vaultKeyId();
        entity.keyAlgorithm = request.keyAlgorithm();
        entity.encryptedVaultKey = request.encryptedVaultKey();
        entity.createdAt = existing == null ? now : existing.createdAt;
        entity.updatedAt = now;
        RecoveryVaultPackageEntity saved = vaultPackages.saveAndFlush(entity);
        audit.recoveryKeyPackageStored(
                username,
                actorId,
                enrollmentId,
                vaultId,
                request.generation(),
                request.vaultKeyId(),
                request.keyAlgorithm());
        return RecoveryVaultPackageResponse.from(saved);
    }

    @Transactional(readOnly = true)
    @NonNull RecoveryVaultPackageResponse getPackage(
            @NonNull String username, @NonNull String enrollmentId, @NonNull String vaultId) {
        RecoveryEnrollmentEntity enrollment =
                enrollments
                        .findByIdUsernameAndIdEnrollmentId(username, enrollmentId)
                        .orElseThrow(
                                () ->
                                        new RecoveryNotFoundException(
                                                "Recovery package does not exist"));
        return vaultPackages
                .findById(
                        new RecoveryVaultPackageId(
                                username, enrollmentId, enrollment.id.generation, vaultId))
                .map(RecoveryVaultPackageResponse::from)
                .orElseThrow(
                        () -> new RecoveryNotFoundException("Recovery package does not exist"));
    }

    private <T> void validate(@NonNull T request) {
        Set<ConstraintViolation<T>> violations = validator.validate(request);
        if (!violations.isEmpty()) {
            ConstraintViolation<T> violation = violations.iterator().next();
            throw new InvalidRecoveryRequestException(violation.getPropertyPath() + " is invalid");
        }
    }

    private void requireRecoveryAlgorithm(@NonNull String algorithm) {
        if (!ServerCryptoAlgorithmRegistry.DEVICE_TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
                .equals(algorithm)) {
            throw new InvalidRecoveryRequestException("Recovery key algorithm is unsupported");
        }
    }
}
