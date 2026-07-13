package top.focess.keystead.server.identity;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@SpringBootTest
@ActiveProfiles("test")
class DeviceTrustRepositoryTest {

    private static final Instant CREATED_AT = Instant.parse("2026-07-12T00:00:00Z");
    private static final Instant ACTION_AT = Instant.parse("2026-07-12T00:01:00Z");
    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private final DeviceRepository devices;
    private final DeviceChallengeRepository challenges;
    private final TransactionTemplate transactions;

    @Autowired
    DeviceTrustRepositoryTest(
            @NonNull DeviceRepository devices,
            @NonNull DeviceChallengeRepository challenges,
            @NonNull PlatformTransactionManager transactionManager) {
        this.devices = devices;
        this.challenges = challenges;
        this.transactions = new TransactionTemplate(transactionManager);
    }

    @Test
    void consumeActiveChallengeHasExactlyOneWinner() {
        String ownerId = "challenge-consume-owner";
        String deviceId = "challenge-consume-device";
        String challengeId = "challenge-consume-id";
        persist(challenge(ownerId, deviceId, challengeId, ACTION_AT.plusSeconds(1)));

        assertEquals(1, consume(ownerId, deviceId, challengeId));
        assertEquals(0, consume(ownerId, deviceId, challengeId));
        assertEquals(ACTION_AT, findChallenge(ownerId, deviceId, challengeId).usedAt());
    }

    @Test
    void consumeActiveChallengeRejectsExactExpiryBoundary() {
        String ownerId = "challenge-expiry-owner";
        String deviceId = "challenge-expiry-device";
        String challengeId = "challenge-expiry-id";
        persist(challenge(ownerId, deviceId, challengeId, ACTION_AT));

        assertEquals(0, consume(ownerId, deviceId, challengeId));
        assertNull(findChallenge(ownerId, deviceId, challengeId).usedAt());
    }

    @Test
    void consumeActiveChallengeLosesAfterStaleUnusedRead() throws Exception {
        String ownerId = "challenge-race-owner";
        String deviceId = "challenge-race-device";
        String challengeId = "challenge-race-id";
        persist(challenge(ownerId, deviceId, challengeId, ACTION_AT.plusSeconds(1)));
        CountDownLatch staleRead = new CountDownLatch(1);
        CountDownLatch winnerCommitted = new CountDownLatch(1);
        ExecutorService executor = Executors.newSingleThreadExecutor();

        try {
            Future<Integer> staleConsumer =
                    executor.submit(
                            () ->
                                    requireNonNull(
                                            transactions.execute(
                                                    ignored -> {
                                                        StoredDeviceChallenge snapshot =
                                                                challenges
                                                                        .find(
                                                                                ownerId,
                                                                                deviceId,
                                                                                challengeId)
                                                                        .orElseThrow();
                                                        assertNull(snapshot.usedAt());
                                                        staleRead.countDown();
                                                        await(
                                                                winnerCommitted,
                                                                "committed challenge consumer");
                                                        return challenges.consumeActive(
                                                                ownerId,
                                                                deviceId,
                                                                challengeId,
                                                                ACTION_AT);
                                                    })));

            await(staleRead, "stale challenge read");
            assertEquals(1, consume(ownerId, deviceId, challengeId));
            winnerCommitted.countDown();

            assertEquals(
                    0,
                    staleConsumer.get(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS),
                    "the transaction with a stale unused snapshot must lose");
            assertEquals(ACTION_AT, findChallenge(ownerId, deviceId, challengeId).usedAt());
        } finally {
            winnerCommitted.countDown();
            executor.shutdownNow();
            assertTrue(
                    executor.awaitTermination(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS),
                    "challenge race executor did not terminate");
        }
    }

    @Test
    void markVerifiedActiveUpdatesBothTrustTimestamps() {
        String ownerId = "device-verify-owner";
        String deviceId = "device-verify-device";
        persist(device(ownerId, deviceId, null));

        assertEquals(1, markVerified(ownerId, deviceId));

        StoredDevice stored = findDevice(ownerId, deviceId);
        assertEquals(ACTION_AT, stored.verifiedAt());
        assertEquals(ACTION_AT, stored.lastSeenAt());
        assertNull(stored.revokedAt());
    }

    @Test
    void markVerifiedActiveRejectsRevokedDevice() {
        String ownerId = "device-verify-revoked-owner";
        String deviceId = "device-verify-revoked-device";
        persist(device(ownerId, deviceId, ACTION_AT.minusSeconds(1)));

        assertEquals(0, markVerified(ownerId, deviceId));
        assertNull(findDevice(ownerId, deviceId).verifiedAt());
    }

    @Test
    void revokeActiveSetsTimestampExactlyOnce() {
        String ownerId = "device-revoke-owner";
        String deviceId = "device-revoke-device";
        persist(device(ownerId, deviceId, null));

        assertEquals(1, revoke(ownerId, deviceId, ACTION_AT));
        assertEquals(0, revoke(ownerId, deviceId, ACTION_AT.plusSeconds(1)));
        assertEquals(ACTION_AT, findDevice(ownerId, deviceId).revokedAt());
    }

    @Test
    void markVerifiedActiveLosesToRevocationCommittedAfterStaleRead() throws Exception {
        String ownerId = "device-verify-race-owner";
        String deviceId = "device-verify-race-device";
        persist(device(ownerId, deviceId, null));
        CountDownLatch staleRead = new CountDownLatch(1);
        CountDownLatch revocationCommitted = new CountDownLatch(1);
        ExecutorService executor = Executors.newSingleThreadExecutor();

        try {
            Future<Integer> staleVerifier =
                    executor.submit(
                            () ->
                                    requireNonNull(
                                            transactions.execute(
                                                    ignored -> {
                                                        StoredDevice snapshot =
                                                                devices.find(ownerId, deviceId)
                                                                        .orElseThrow();
                                                        assertNull(snapshot.revokedAt());
                                                        staleRead.countDown();
                                                        await(
                                                                revocationCommitted,
                                                                "committed device revocation");
                                                        return devices.markVerifiedActive(
                                                                ownerId, deviceId, ACTION_AT);
                                                    })));

            await(staleRead, "stale device read");
            assertEquals(1, revoke(ownerId, deviceId, ACTION_AT.minusSeconds(1)));
            revocationCommitted.countDown();

            assertEquals(
                    0,
                    staleVerifier.get(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS),
                    "the transaction with a stale active snapshot must lose");
            StoredDevice stored = findDevice(ownerId, deviceId);
            assertNull(stored.verifiedAt());
            assertEquals(ACTION_AT.minusSeconds(1), stored.revokedAt());
        } finally {
            revocationCommitted.countDown();
            executor.shutdownNow();
            assertTrue(
                    executor.awaitTermination(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS),
                    "device race executor did not terminate");
        }
    }

    @Test
    void revokeActivePreservesVerificationCommittedAfterStaleRead() throws Exception {
        String ownerId = "device-revoke-race-owner";
        String deviceId = "device-revoke-race-device";
        Instant revokedAt = ACTION_AT.plusSeconds(1);
        persist(device(ownerId, deviceId, null));
        CountDownLatch staleRead = new CountDownLatch(1);
        CountDownLatch verificationCommitted = new CountDownLatch(1);
        ExecutorService executor = Executors.newSingleThreadExecutor();

        try {
            Future<Integer> staleRevoker =
                    executor.submit(
                            () ->
                                    requireNonNull(
                                            transactions.execute(
                                                    ignored -> {
                                                        StoredDevice snapshot =
                                                                devices.find(ownerId, deviceId)
                                                                        .orElseThrow();
                                                        assertNull(snapshot.verifiedAt());
                                                        assertNull(snapshot.revokedAt());
                                                        staleRead.countDown();
                                                        await(
                                                                verificationCommitted,
                                                                "committed device verification");
                                                        return devices.revokeActive(
                                                                ownerId, deviceId, revokedAt);
                                                    })));

            await(staleRead, "stale active device read");
            assertEquals(1, markVerified(ownerId, deviceId));
            verificationCommitted.countDown();

            assertEquals(
                    1,
                    staleRevoker.get(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS),
                    "the transaction with a stale active snapshot must revoke conditionally");
            StoredDevice stored = findDevice(ownerId, deviceId);
            assertEquals(ACTION_AT, stored.verifiedAt());
            assertEquals(ACTION_AT, stored.lastSeenAt());
            assertEquals(revokedAt, stored.revokedAt());
        } finally {
            verificationCommitted.countDown();
            executor.shutdownNow();
            assertTrue(
                    executor.awaitTermination(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS),
                    "reverse device race executor did not terminate");
        }
    }

    private void persist(@NonNull StoredDevice device) {
        transactions.executeWithoutResult(ignored -> devices.insert(device));
    }

    private void persist(@NonNull StoredDeviceChallenge challenge) {
        transactions.executeWithoutResult(ignored -> challenges.insert(challenge));
    }

    private int consume(
            @NonNull String ownerId, @NonNull String deviceId, @NonNull String challengeId) {
        return requireNonNull(
                transactions.execute(
                        ignored ->
                                challenges.consumeActive(
                                        ownerId, deviceId, challengeId, ACTION_AT)));
    }

    private int markVerified(@NonNull String ownerId, @NonNull String deviceId) {
        return requireNonNull(
                transactions.execute(
                        ignored -> devices.markVerifiedActive(ownerId, deviceId, ACTION_AT)));
    }

    private int revoke(
            @NonNull String ownerId, @NonNull String deviceId, @NonNull Instant revokedAt) {
        return requireNonNull(
                transactions.execute(
                        ignored -> devices.revokeActive(ownerId, deviceId, revokedAt)));
    }

    private @NonNull StoredDevice findDevice(@NonNull String ownerId, @NonNull String deviceId) {
        return requireNonNull(
                transactions.execute(ignored -> devices.find(ownerId, deviceId).orElseThrow()));
    }

    private @NonNull StoredDeviceChallenge findChallenge(
            @NonNull String ownerId, @NonNull String deviceId, @NonNull String challengeId) {
        return requireNonNull(
                transactions.execute(
                        ignored -> challenges.find(ownerId, deviceId, challengeId).orElseThrow()));
    }

    private static @NonNull StoredDevice device(
            @NonNull String ownerId, @NonNull String deviceId, Instant revokedAt) {
        return new StoredDevice(
                ownerId,
                deviceId,
                "ED25519",
                "proof-public-key",
                CREATED_AT,
                null,
                null,
                revokedAt);
    }

    private static @NonNull StoredDeviceChallenge challenge(
            @NonNull String ownerId,
            @NonNull String deviceId,
            @NonNull String challengeId,
            @NonNull Instant expiresAt) {
        return new StoredDeviceChallenge(
                ownerId, deviceId, challengeId, "nonce", expiresAt, null, CREATED_AT);
    }

    private static void await(@NonNull CountDownLatch latch, @NonNull String event) {
        try {
            assertTrue(
                    latch.await(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS),
                    () -> "Timed out waiting for " + event);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new AssertionError("Interrupted while waiting for " + event, exception);
        }
    }
}
