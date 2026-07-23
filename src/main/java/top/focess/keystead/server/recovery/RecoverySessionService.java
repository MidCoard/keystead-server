package top.focess.keystead.server.recovery;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
class RecoverySessionService {

    private static final Duration CHALLENGE_TTL = Duration.ofMinutes(5);
    private static final Duration SESSION_TTL = Duration.ofMinutes(10);
    private static final int MAX_ATTEMPTS = 5;
    private static final int RANDOM_BYTES = 32;

    private final RecoveryChallengeRepository challenges;
    private final RecoveryEnrollmentRepository enrollments;
    private final RecoverySessionRepository sessions;
    private final RecoveryVaultPackageRepository vaultPackages;
    private final PasswordEncoder passwordEncoder;
    private final Validator validator;
    private final Clock clock;
    private final SecureRandom secureRandom = new SecureRandom();
    private final String dummyCredentialHash;

    RecoverySessionService(
            @NonNull RecoveryChallengeRepository challenges,
            @NonNull RecoveryEnrollmentRepository enrollments,
            @NonNull RecoverySessionRepository sessions,
            @NonNull RecoveryVaultPackageRepository vaultPackages,
            @NonNull PasswordEncoder passwordEncoder,
            @NonNull Validator validator,
            @NonNull Clock clock) {
        this.challenges = challenges;
        this.enrollments = enrollments;
        this.sessions = sessions;
        this.vaultPackages = vaultPackages;
        this.passwordEncoder = passwordEncoder;
        this.validator = validator;
        this.clock = clock;
        this.dummyCredentialHash =
                passwordEncoder.encode("keystead-recovery-unknown-" + UUID.randomUUID());
    }

    @Transactional
    @NonNull RecoveryChallengeResponse createChallenge(@NonNull RecoveryChallengeRequest request) {
        validate(request);
        @Nullable RecoveryEnrollmentEntity enrollment =
                enrollments
                        .findById(
                                new RecoveryEnrollmentId(
                                        request.username(),
                                        request.enrollmentId(),
                                        request.generation()))
                        .filter(value -> value.state == RecoveryEnrollmentState.ACTIVE)
                        .orElse(null);

        Instant now = clock.instant();
        RecoveryChallengeEntity challenge = new RecoveryChallengeEntity();
        challenge.challengeId = UUID.randomUUID().toString();
        challenge.username = request.username();
        challenge.enrollmentId = enrollment == null ? null : enrollment.id.enrollmentId;
        challenge.generation = enrollment == null ? null : enrollment.id.generation;
        challenge.expiresAt = now.plus(CHALLENGE_TTL);
        challenge.attempts = 0;
        challenge.createdAt = now;
        challenges.saveAndFlush(challenge);
        return new RecoveryChallengeResponse(challenge.challengeId, challenge.expiresAt);
    }

    @Transactional
    @NonNull RecoverySessionResponse verifyKit(@NonNull RecoveryCredentialRequest request) {
        validate(request);
        Instant now = clock.instant();
        if (challenges.claimAttempt(request.challengeId(), now, MAX_ATTEMPTS) != 1) {
            throw new RecoveryAuthenticationFailedException();
        }
        RecoveryChallengeEntity challenge =
                challenges
                        .findById(request.challengeId())
                        .orElseThrow(RecoveryAuthenticationFailedException::new);
        @Nullable RecoveryEnrollmentEntity enrollment = enrollmentFor(challenge);
        String credentialHash =
                enrollment == null ? dummyCredentialHash : enrollment.credentialHash;
        boolean matches = passwordEncoder.matches(request.accountCredential(), credentialHash);
        if (!matches || enrollment == null) {
            throw new RecoveryAuthenticationFailedException();
        }
        if (challenges.consumeActive(challenge.challengeId, now) != 1) {
            throw new RecoveryAuthenticationFailedException();
        }

        String token = randomToken();
        Instant expiresAt = now.plus(SESSION_TTL);
        RecoverySessionEntity session = new RecoverySessionEntity();
        session.tokenHash = tokenHash(token);
        session.username = challenge.username;
        session.authority = RecoveryAuthority.KIT;
        session.enrollmentId = enrollment.id.enrollmentId;
        session.generation = enrollment.id.generation;
        session.expiresAt = expiresAt;
        session.createdAt = now;
        sessions.saveAndFlush(session);
        return new RecoverySessionResponse(token, expiresAt);
    }

    @Transactional(readOnly = true)
    @NonNull RecoveryMaterialResponse material(@Nullable String authorization) {
        RecoverySessionEntity session = requireActiveSession(authorization);
        if (session.authority != RecoveryAuthority.KIT
                || session.enrollmentId == null
                || session.generation == null) {
            throw new RecoveryAuthenticationFailedException();
        }
        RecoveryEnrollmentEntity enrollment =
                enrollments
                        .findById(
                                new RecoveryEnrollmentId(
                                        session.username, session.enrollmentId, session.generation))
                        .orElseThrow(RecoveryAuthenticationFailedException::new);
        List<RecoveryVaultPackageResponse> packages =
                vaultPackages
                        .listForEnrollment(
                                session.username, session.enrollmentId, session.generation)
                        .stream()
                        .map(RecoveryVaultPackageResponse::from)
                        .toList();
        return new RecoveryMaterialResponse(
                enrollment.id.enrollmentId,
                enrollment.id.generation,
                enrollment.wrappingAlgorithm,
                enrollment.encryptedPrivateKey,
                packages);
    }

    @Transactional(readOnly = true)
    @NonNull RecoverySessionEntity requireActiveSession(@Nullable String authorization) {
        String token = recoveryToken(authorization);
        return sessions.findActive(tokenHash(token), clock.instant())
                .orElseThrow(RecoveryAuthenticationFailedException::new);
    }

    @NonNull RecoverySessionResponse issueDeviceSession(
            @NonNull RecoveryRequestEntity request, @NonNull Instant now) {
        String token = randomToken();
        Instant expiresAt = now.plus(SESSION_TTL);
        RecoverySessionEntity session = new RecoverySessionEntity();
        session.tokenHash = tokenHash(token);
        session.username = request.username;
        session.authority = RecoveryAuthority.DEVICE_APPROVAL;
        session.requestId = request.requestId;
        session.expiresAt = expiresAt;
        session.createdAt = now;
        sessions.saveAndFlush(session);
        return new RecoverySessionResponse(token, expiresAt);
    }

    private @Nullable RecoveryEnrollmentEntity enrollmentFor(
            @NonNull RecoveryChallengeEntity challenge) {
        if (challenge.enrollmentId == null || challenge.generation == null) {
            return null;
        }
        return enrollments
                .findById(
                        new RecoveryEnrollmentId(
                                challenge.username, challenge.enrollmentId, challenge.generation))
                .filter(value -> value.state == RecoveryEnrollmentState.ACTIVE)
                .orElse(null);
    }

    private @NonNull String recoveryToken(@Nullable String authorization) {
        if (authorization == null || !authorization.startsWith("Recovery ")) {
            throw new RecoveryAuthenticationFailedException();
        }
        String token = authorization.substring("Recovery ".length());
        if (token.isBlank() || token.length() > RecoveryLimits.RECOVERY_TOKEN_MAX_LENGTH) {
            throw new RecoveryAuthenticationFailedException();
        }
        return token;
    }

    private @NonNull String randomToken() {
        byte[] value = new byte[RANDOM_BYTES];
        secureRandom.nextBytes(value);
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
        } finally {
            java.util.Arrays.fill(value, (byte) 0);
        }
    }

    private @NonNull String tokenHash(@NonNull String token) {
        byte[] encoded = token.getBytes(StandardCharsets.US_ASCII);
        try {
            return Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(MessageDigest.getInstance("SHA-256").digest(encoded));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        } finally {
            java.util.Arrays.fill(encoded, (byte) 0);
        }
    }

    private <T> void validate(@NonNull T request) {
        Set<ConstraintViolation<T>> violations = validator.validate(request);
        if (!violations.isEmpty()) {
            throw new InvalidRecoveryRequestException("Recovery request is invalid");
        }
    }
}
