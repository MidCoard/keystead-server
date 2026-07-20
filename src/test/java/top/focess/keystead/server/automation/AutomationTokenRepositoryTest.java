package top.focess.keystead.server.automation;

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
class AutomationTokenRepositoryTest {

    private static final Instant CREATED_AT = Instant.parse("2026-07-12T00:00:00Z");
    private static final Instant TOUCH_AT = Instant.parse("2026-07-12T00:02:00Z");
    private static final Instant REVOKED_AT = Instant.parse("2026-07-12T00:01:00Z");
    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private final AutomationTokenRepository tokens;
    private final TransactionTemplate transactions;

    @Autowired
    AutomationTokenRepositoryTest(
            @NonNull AutomationTokenRepository tokens,
            @NonNull PlatformTransactionManager transactionManager) {
        this.tokens = tokens;
        this.transactions = new TransactionTemplate(transactionManager);
    }

    @Test
    void touchActiveUpdatesLastUsedAtForActiveUnexpiredToken() {
        String tokenHash = "automation-token-touch-active";
        persist(token(tokenHash, TOUCH_AT.plusSeconds(60), null));

        int updated = touch(tokenHash);

        assertEquals(1, updated);
        AutomationToken stored = find(tokenHash);
        assertEquals(TOUCH_AT, stored.lastUsedAt());
        assertNull(stored.revokedAt());
    }

    @Test
    void touchActiveDoesNotUpdateRevokedToken() {
        String tokenHash = "automation-token-touch-revoked";
        persist(token(tokenHash, TOUCH_AT.plusSeconds(60), REVOKED_AT));

        int updated = touch(tokenHash);

        assertEquals(0, updated);
        AutomationToken stored = find(tokenHash);
        assertEquals(REVOKED_AT, stored.revokedAt());
        assertNull(stored.lastUsedAt());
    }

    @Test
    void touchActiveDoesNotUpdateExpiredToken() {
        String tokenHash = "automation-token-touch-expired";
        persist(token(tokenHash, TOUCH_AT.minusSeconds(1), null));

        int updated = touch(tokenHash);

        assertEquals(0, updated);
        assertNull(find(tokenHash).lastUsedAt());
    }

    @Test
    void touchActiveDoesNotUpdateTokenAtExpiryBoundary() {
        String tokenHash = "automation-token-touch-boundary";
        persist(token(tokenHash, TOUCH_AT, null));

        int updated = touch(tokenHash);

        assertEquals(0, updated);
        assertNull(find(tokenHash).lastUsedAt());
    }

    @Test
    void touchActiveDoesNotUpdateMissingToken() {
        assertEquals(0, touch("automation-token-touch-missing"));
    }

    @Test
    void touchActiveLosesToRevokeCommittedAfterStaleRead() throws Exception {
        String tokenHash = "automation-token-touch-stale-read";
        persist(token(tokenHash, TOUCH_AT.plusSeconds(60), null));
        CountDownLatch tokenRead = new CountDownLatch(1);
        CountDownLatch revokeCommitted = new CountDownLatch(1);
        ExecutorService executor = Executors.newSingleThreadExecutor();

        try {
            Future<Integer> touchResult =
                    executor.submit(
                            () ->
                                    requireNonNull(
                                            transactions.execute(
                                                    ignored -> {
                                                        AutomationToken snapshot =
                                                                tokens.find(tokenHash)
                                                                        .orElseThrow();
                                                        assertNull(snapshot.revokedAt());
                                                        tokenRead.countDown();
                                                        await(
                                                                revokeCommitted,
                                                                "committed token revocation");
                                                        return tokens.touchActive(
                                                                tokenHash, TOUCH_AT);
                                                    })));

            await(tokenRead, "transaction A token read");
            transactions.executeWithoutResult(
                    ignored -> {
                        AutomationToken current = tokens.find(tokenHash).orElseThrow();
                        tokens.persist(
                                new AutomationToken(
                                        current.tokenHash(),
                                        current.ownerId(),
                                        current.principalId(),
                                        current.vaultId(),
                                        current.scopes(),
                                        current.expiresAt(),
                                        current.createdAt(),
                                        REVOKED_AT,
                                        current.lastUsedAt(),
                                        current.tokenId(),
                                        current.grantedSecretIds()));
                    });
            revokeCommitted.countDown();

            assertEquals(
                    0,
                    touchResult.get(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS),
                    "transaction A must observe transaction B's committed revocation");
            AutomationToken stored = find(tokenHash);
            assertEquals(REVOKED_AT, stored.revokedAt());
            assertNull(stored.lastUsedAt());
        } finally {
            revokeCommitted.countDown();
            executor.shutdownNow();
            assertTrue(
                    executor.awaitTermination(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS),
                    "automation token race executor did not terminate");
        }
    }

    private void persist(@NonNull AutomationToken token) {
        transactions.executeWithoutResult(ignored -> tokens.persist(token));
    }

    private int touch(@NonNull String tokenHash) {
        return requireNonNull(
                transactions.execute(ignored -> tokens.touchActive(tokenHash, TOUCH_AT)));
    }

    private @NonNull AutomationToken find(@NonNull String tokenHash) {
        return requireNonNull(
                transactions.execute(ignored -> tokens.find(tokenHash).orElseThrow()));
    }

    private static @NonNull AutomationToken token(
            @NonNull String tokenHash, @NonNull Instant expiresAt, Instant revokedAt) {
        return new AutomationToken(
                tokenHash,
                "automation-token-owner",
                "automation-token-principal",
                "automation-token-vault",
                AutomationScope.READ_VAULT_KEY_PACKAGE.name(),
                expiresAt,
                CREATED_AT,
                revokedAt,
                null,
                tokenHash + "-id",
                "");
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
