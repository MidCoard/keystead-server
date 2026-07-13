package top.focess.keystead.server.recovery;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.server.audit.AuditService;
import top.focess.keystead.server.auth.AuthSessionRevocationService;
import top.focess.keystead.server.identity.IdentityRecoveryService;
import top.focess.keystead.server.identity.RecoveryDeviceRegistration;
import top.focess.keystead.server.vault.RecoveryDeviceVaultPackage;
import top.focess.keystead.server.vault.VaultRecoveryPackageService;

@Service
class RecoveryCompletionService {

    private final RecoverySessionService sessionService;
    private final RecoverySessionRepository sessions;
    private final RecoveryEnrollmentRepository enrollments;
    private final RecoveryVaultPackageRepository recoveryPackages;
    private final RecoveryRequestRepository requests;
    private final RecoveryRequestVaultPackageRepository requestPackages;
    private final IdentityRecoveryService identity;
    private final AuthSessionRevocationService authSessions;
    private final VaultRecoveryPackageService vaultPackages;
    private final PasswordEncoder passwordEncoder;
    private final Validator validator;
    private final Clock clock;
    private final AuditService audit;

    RecoveryCompletionService(
            @NonNull RecoverySessionService sessionService,
            @NonNull RecoverySessionRepository sessions,
            @NonNull RecoveryEnrollmentRepository enrollments,
            @NonNull RecoveryVaultPackageRepository recoveryPackages,
            @NonNull RecoveryRequestRepository requests,
            @NonNull RecoveryRequestVaultPackageRepository requestPackages,
            @NonNull IdentityRecoveryService identity,
            @NonNull AuthSessionRevocationService authSessions,
            @NonNull VaultRecoveryPackageService vaultPackages,
            @NonNull PasswordEncoder passwordEncoder,
            @NonNull Validator validator,
            @NonNull Clock clock,
            @NonNull AuditService audit) {
        this.sessionService = sessionService;
        this.sessions = sessions;
        this.enrollments = enrollments;
        this.recoveryPackages = recoveryPackages;
        this.requests = requests;
        this.requestPackages = requestPackages;
        this.identity = identity;
        this.authSessions = authSessions;
        this.vaultPackages = vaultPackages;
        this.passwordEncoder = passwordEncoder;
        this.validator = validator;
        this.clock = clock;
        this.audit = audit;
    }

    @Transactional
    @NonNull RecoveryCompletionResponse complete(
            @NonNull String authorization, @NonNull RecoveryCompletionRequest completion) {
        RecoverySessionEntity session = sessionService.requireActiveSession(authorization);
        validate(completion);
        Instant now = clock.instant();
        if (sessions.consumeActive(session.tokenHash, now) != 1) {
            throw new RecoveryAuthenticationFailedException();
        }

        RecoveryDeviceRegistration registration = registration(session, completion);
        List<RecoveryDeviceVaultPackage> packages = packages(session, completion);
        Set<String> availableVaultIds = availableVaultIds(session);
        String passwordHash = passwordEncoder.encode(completion.newPassword());

        identity.resetPasswordAndEnrollVerifiedDevice(
                session.username, passwordHash, registration, now);
        List<String> recoveredVaultIds =
                vaultPackages.store(session.username, registration.deviceId(), packages).stream()
                        .sorted()
                        .toList();
        authSessions.revokeAll(session.username, now);
        consumeAuthority(session, now);

        Set<String> pending = new HashSet<>(availableVaultIds);
        pending.removeAll(recoveredVaultIds);
        audit.recoveryCompleted(
                session.username,
                registration.deviceId(),
                session.authority.name(),
                recoveredVaultIds.size(),
                pending.size());
        return new RecoveryCompletionResponse(
                true,
                registration.deviceId(),
                recoveredVaultIds,
                pending.stream().sorted().toList(),
                true);
    }

    private @NonNull RecoveryDeviceRegistration registration(
            @NonNull RecoverySessionEntity session, @NonNull RecoveryCompletionRequest completion) {
        if (session.authority == RecoveryAuthority.DEVICE_APPROVAL) {
            RecoveryRequestEntity request = deviceRequest(session);
            if (!request.deviceId.equals(completion.deviceId())
                    || !request.proofKeyAlgorithm.equals(completion.proofKeyAlgorithm())
                    || !request.proofPublicKey.equals(completion.proofPublicKey())
                    || !request.wrappingKeyAlgorithm.equals(completion.wrappingKeyAlgorithm())
                    || !request.wrappingPublicKey.equals(completion.wrappingPublicKey())) {
                throw new InvalidRecoveryRequestException(
                        "Replacement device does not match approved request");
            }
        }
        return new RecoveryDeviceRegistration(
                completion.deviceId(),
                completion.proofKeyAlgorithm(),
                completion.proofPublicKey(),
                completion.wrappingKeyAlgorithm(),
                completion.wrappingPublicKey());
    }

    private @NonNull List<RecoveryDeviceVaultPackage> packages(
            @NonNull RecoverySessionEntity session, @NonNull RecoveryCompletionRequest completion) {
        List<RecoveryDeviceVaultPackage> values = new ArrayList<>();
        if (session.authority == RecoveryAuthority.DEVICE_APPROVAL) {
            for (RecoveryRequestVaultPackageEntity entity :
                    requestPackages.listForRequest(deviceRequest(session).requestId)) {
                values.add(
                        new RecoveryDeviceVaultPackage(
                                entity.id.vaultId,
                                entity.vaultKeyId,
                                entity.keyAlgorithm,
                                entity.encryptedVaultKey));
            }
        }
        for (RecoveryCompletionVaultPackage value : completion.vaultPackages()) {
            values.add(
                    new RecoveryDeviceVaultPackage(
                            value.vaultId(),
                            value.vaultKeyId(),
                            value.keyAlgorithm(),
                            value.encryptedVaultKey()));
        }
        Set<String> vaultIds = new HashSet<>();
        for (RecoveryDeviceVaultPackage value : values) {
            if (!vaultIds.add(value.vaultId())) {
                throw new InvalidRecoveryRequestException(
                        "Recovery completion contains duplicate vault package");
            }
        }
        return values;
    }

    private @NonNull Set<String> availableVaultIds(@NonNull RecoverySessionEntity session) {
        Set<String> available = new HashSet<>();
        if (session.authority == RecoveryAuthority.KIT
                && session.enrollmentId != null
                && session.generation != null) {
            recoveryPackages
                    .listForEnrollment(session.username, session.enrollmentId, session.generation)
                    .forEach(value -> available.add(value.id.vaultId));
        } else if (session.authority == RecoveryAuthority.DEVICE_APPROVAL) {
            requestPackages
                    .listForRequest(deviceRequest(session).requestId)
                    .forEach(value -> available.add(value.id.vaultId));
        }
        return available;
    }

    private @NonNull RecoveryRequestEntity deviceRequest(@NonNull RecoverySessionEntity session) {
        if (session.requestId == null) {
            throw new RecoveryAuthenticationFailedException();
        }
        return requests.findById(session.requestId)
                .filter(value -> value.state == RecoveryRequestState.CONSUMED)
                .orElseThrow(RecoveryAuthenticationFailedException::new);
    }

    private void consumeAuthority(@NonNull RecoverySessionEntity session, @NonNull Instant now) {
        if (session.authority != RecoveryAuthority.KIT) {
            return;
        }
        if (session.enrollmentId == null
                || session.generation == null
                || enrollments.consumeActive(
                                session.username, session.enrollmentId, session.generation, now)
                        != 1) {
            throw new RecoveryAuthenticationFailedException();
        }
    }

    private void validate(@NonNull RecoveryCompletionRequest request) {
        Set<ConstraintViolation<RecoveryCompletionRequest>> violations =
                validator.validate(request);
        if (!violations.isEmpty()) {
            throw new InvalidRecoveryRequestException("Recovery completion is invalid");
        }
    }
}
