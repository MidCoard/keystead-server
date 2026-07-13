package top.focess.keystead.server.recovery;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

import jakarta.persistence.EntityManager;
import java.time.Instant;
import org.hibernate.exception.ConstraintViolationException;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@SpringBootTest
@ActiveProfiles("test")
class RecoveryPersistenceTest {

    private static final Instant NOW = Instant.parse("2026-07-14T00:00:00Z");

    private final RecoveryEnrollmentRepository enrollments;
    private final RecoveryVaultPackageRepository vaultPackages;
    private final RecoveryChallengeRepository challenges;
    private final RecoveryRequestRepository requests;
    private final RecoverySessionRepository sessions;
    private final EntityManager entityManager;
    private final TransactionTemplate transactions;

    @Autowired
    RecoveryPersistenceTest(
            @NonNull RecoveryEnrollmentRepository enrollments,
            @NonNull RecoveryVaultPackageRepository vaultPackages,
            @NonNull RecoveryChallengeRepository challenges,
            @NonNull RecoveryRequestRepository requests,
            @NonNull RecoverySessionRepository sessions,
            @NonNull EntityManager entityManager,
            @NonNull PlatformTransactionManager transactionManager) {
        this.enrollments = enrollments;
        this.vaultPackages = vaultPackages;
        this.challenges = challenges;
        this.requests = requests;
        this.sessions = sessions;
        this.entityManager = entityManager;
        this.transactions = new TransactionTemplate(transactionManager);
    }

    @Test
    void repositoriesRoundTripOnlyHashedPublicOrEncryptedRecoveryState() {
        RecoveryEnrollmentEntity enrollment = enrollment("alice", "enrollment-1", 1L, "A");
        enrollments.saveAndFlush(enrollment);

        RecoveryVaultPackageEntity keyPackage = new RecoveryVaultPackageEntity();
        keyPackage.id = new RecoveryVaultPackageId("alice", "enrollment-1", 1L, "vault-1");
        keyPackage.vaultKeyId = "vault-key-1";
        keyPackage.keyAlgorithm = "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM";
        keyPackage.encryptedVaultKey = "opaque-recovery-ciphertext";
        keyPackage.createdAt = NOW;
        keyPackage.updatedAt = NOW;
        vaultPackages.saveAndFlush(keyPackage);

        RecoveryChallengeEntity challenge = new RecoveryChallengeEntity();
        challenge.challengeId = "challenge-1";
        challenge.username = "alice";
        challenge.enrollmentId = "enrollment-1";
        challenge.generation = 1L;
        challenge.expiresAt = NOW.plusSeconds(300);
        challenge.attempts = 0;
        challenge.createdAt = NOW;
        challenges.saveAndFlush(challenge);

        RecoveryRequestEntity request = new RecoveryRequestEntity();
        request.requestId = "request-1";
        request.username = "alice";
        request.nonce = "nonce-1";
        request.fingerprint = "AAAA-BBBB-CCCC-DDDD-EEEE";
        request.deviceId = "laptop-2";
        request.proofKeyAlgorithm = "ED25519";
        request.proofPublicKey = "proof-public-key";
        request.wrappingKeyAlgorithm = "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM";
        request.wrappingPublicKey = "wrapping-public-key";
        request.state = RecoveryRequestState.PENDING;
        request.expiresAt = NOW.plusSeconds(300);
        request.createdAt = NOW;
        requests.saveAndFlush(request);

        RecoverySessionEntity session = new RecoverySessionEntity();
        session.tokenHash = "sha256-session-token";
        session.username = "alice";
        session.authority = RecoveryAuthority.KIT;
        session.enrollmentId = "enrollment-1";
        session.generation = 1L;
        session.expiresAt = NOW.plusSeconds(600);
        session.createdAt = NOW;
        sessions.saveAndFlush(session);

        assertEquals(
                "credential-hash",
                enrollments.findById(enrollment.id).orElseThrow().credentialHash);
        assertEquals(
                "opaque-recovery-ciphertext",
                vaultPackages.findById(keyPackage.id).orElseThrow().encryptedVaultKey);
        assertEquals(0, challenges.findById("challenge-1").orElseThrow().attempts);
        assertEquals(
                RecoveryRequestState.PENDING, requests.findById("request-1").orElseThrow().state);
        assertEquals(
                RecoveryAuthority.KIT,
                sessions.findById("sha256-session-token").orElseThrow().authority);
    }

    @Test
    void databaseAllowsOnlyOneActiveEnrollmentPerUser() {
        transactions.executeWithoutResult(
                ignored -> enrollments.saveAndFlush(enrollment("unique-alice", "first", 1L, "A")));

        ConstraintViolationException error =
                assertThrows(
                        ConstraintViolationException.class,
                        () ->
                                transactions.executeWithoutResult(
                                        ignored -> {
                                            entityManager.persist(
                                                    enrollment("unique-alice", "second", 2L, "A"));
                                            entityManager.flush();
                                        }));
        assertThat(error.getConstraintName())
                .containsIgnoringCase("ux_recovery_enrollment_lifecycle");
    }

    @Test
    void databaseRejectsAttemptCountOutsideBound() {
        RecoveryChallengeEntity challenge = new RecoveryChallengeEntity();
        challenge.challengeId = "attempt-overflow";
        challenge.username = "alice";
        challenge.expiresAt = NOW.plusSeconds(300);
        challenge.attempts = 6;
        challenge.createdAt = NOW;

        ConstraintViolationException error =
                assertThrows(
                        ConstraintViolationException.class,
                        () ->
                                transactions.executeWithoutResult(
                                        ignored -> {
                                            entityManager.persist(challenge);
                                            entityManager.flush();
                                        }));
        assertThat(error.getConstraintName())
                .containsIgnoringCase("ck_recovery_challenge_attempts");
    }

    @Test
    void databaseRejectsMixedRecoverySessionAuthorityFields() {
        RecoverySessionEntity session = new RecoverySessionEntity();
        session.tokenHash = "mixed-authority";
        session.username = "alice";
        session.authority = RecoveryAuthority.KIT;
        session.enrollmentId = "enrollment-1";
        session.generation = 1L;
        session.requestId = "request-should-be-null";
        session.expiresAt = NOW.plusSeconds(600);
        session.createdAt = NOW;

        ConstraintViolationException error =
                assertThrows(
                        ConstraintViolationException.class,
                        () ->
                                transactions.executeWithoutResult(
                                        ignored -> {
                                            entityManager.persist(session);
                                            entityManager.flush();
                                        }));
        assertThat(error.getConstraintName()).containsIgnoringCase("ck_recovery_session_authority");
    }

    private static @NonNull RecoveryEnrollmentEntity enrollment(
            @NonNull String username,
            @NonNull String enrollmentId,
            long generation,
            @NonNull String marker) {
        RecoveryEnrollmentEntity enrollment = new RecoveryEnrollmentEntity();
        enrollment.id = new RecoveryEnrollmentId(username, enrollmentId, generation);
        enrollment.credentialHash = "credential-hash";
        enrollment.wrappingAlgorithm = "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM";
        enrollment.wrappingPublicKey = "recovery-public-key";
        enrollment.encryptedPrivateKey = "encrypted-recovery-private-key";
        enrollment.state = RecoveryEnrollmentState.ACTIVE;
        enrollment.lifecycleMarker = marker;
        enrollment.createdAt = NOW;
        enrollment.committedAt = NOW;
        return enrollment;
    }
}
