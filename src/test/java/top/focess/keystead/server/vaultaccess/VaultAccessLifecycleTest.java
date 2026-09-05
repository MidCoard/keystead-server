package top.focess.keystead.server.vaultaccess;

import static org.junit.jupiter.api.Assertions.*;

import jakarta.validation.Validator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import top.focess.keystead.crypto.DefaultCryptoService;

@SpringBootTest
@ActiveProfiles("test")
class VaultAccessLifecycleTest {
    @Autowired private VaultAccessRequestService service;
    @Autowired private VaultAccessRequestRepository requests;
    @Autowired private Validator validator;
    @Autowired private PlatformTransactionManager transactions;

    @Test
    void duplicateIdsCannotChangeTheOwnerOrApprovedPackage() {
        String id = UUID.randomUUID().toString();
        var original = service.create("collision-owner", request(id));
        service.approve("collision-owner", id, approval());

        assertThrows(
                InvalidVaultAccessRequestException.class,
                () -> service.create("collision-owner", request(id)));
        assertThrows(
                InvalidVaultAccessRequestException.class,
                () -> service.create("collision-outsider", request(id)));

        var preserved = service.status("collision-owner", id);
        assertEquals(original.fingerprint(), preserved.fingerprint());
        assertEquals(original.expiresAt(), preserved.expiresAt());
        assertEquals(VaultAccessRequestState.APPROVED, preserved.state());
        assertEquals("wrapped-key", preserved.approvedPackage().encryptedVaultKey());
        assertThrows(
                VaultAccessRequestNotFoundException.class,
                () -> service.status("collision-outsider", id));
    }

    @Test
    void concurrentCreationOfTheSameIdHasOneWinner() throws Exception {
        String id = UUID.randomUUID().toString();
        var inserted = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var attempted = new CountDownLatch(1);
        try (var pool = Executors.newVirtualThreadPerTaskExecutor()) {
            var first =
                    pool.submit(
                            () ->
                                    new TransactionTemplate(transactions)
                                            .execute(
                                                    status -> {
                                                        var value =
                                                                service.create(
                                                                        "race-owner", request(id));
                                                        inserted.countDown();
                                                        await(release);
                                                        return value;
                                                    }));
            await(inserted);
            try {
                var second =
                        pool.submit(
                                () -> {
                                    attempted.countDown();
                                    return service.create("race-outsider", request(id));
                                });
                await(attempted);
                assertThrows(TimeoutException.class, () -> second.get(200, TimeUnit.MILLISECONDS));
                release.countDown();
                first.get(5, TimeUnit.SECONDS);
                assertInstanceOf(
                        InvalidVaultAccessRequestException.class,
                        assertThrows(
                                        ExecutionException.class,
                                        () -> second.get(5, TimeUnit.SECONDS))
                                .getCause());
                assertEquals("race-owner", service.status("race-owner", id).accountId());
                assertThrows(
                        VaultAccessRequestNotFoundException.class,
                        () -> service.status("race-outsider", id));
            } finally {
                release.countDown();
            }
        }
    }

    @Test
    void approvedPackageIsAvailableBeforeExpiryButNotAtOrAfterIt() {
        String id = UUID.randomUUID().toString();
        var created = service.create("expiry-owner", request(id));
        service.approve("expiry-owner", id, approval());

        var before = at(created.expiresAt().minusNanos(1)).status("expiry-owner", id);
        assertEquals(VaultAccessRequestState.APPROVED, before.state());
        assertNotNull(before.approvedPackage());
        for (Instant now :
                new Instant[] {created.expiresAt(), created.expiresAt().plusSeconds(1)}) {
            var expired = at(now).status("expiry-owner", id);
            assertEquals(VaultAccessRequestState.EXPIRED, expired.state());
            assertNull(expired.approvedPackage());
        }
    }

    @Test
    void expirySweepDeletesPendingAndApprovedMaterialButKeepsLiveRequests() {
        String pending = UUID.randomUUID().toString();
        String approved = UUID.randomUUID().toString();
        String live = UUID.randomUUID().toString();
        var earlier = at(Instant.now().minusSeconds(3600));
        new TransactionTemplate(transactions)
                .executeWithoutResult(
                        status -> {
                            earlier.create("sweep-owner", request(pending));
                            earlier.create("sweep-owner", request(approved));
                            earlier.approve("sweep-owner", approved, approval());
                        });
        service.create("sweep-owner", request(live));

        service.purgeExpiredRequests();

        assertFalse(requests.existsById(pending));
        assertFalse(requests.existsById(approved));
        assertTrue(requests.existsById(live));
        assertThrows(
                VaultAccessRequestNotFoundException.class,
                () -> service.status("sweep-owner", approved));
    }

    @Test
    void expirySweepRemovesMaterialAtTheExactExpiryBoundary() {
        String id = UUID.randomUUID().toString();
        var created = service.create("boundary-owner", request(id));
        service.approve("boundary-owner", id, approval());
        new TransactionTemplate(transactions)
                .executeWithoutResult(status -> at(created.expiresAt()).purgeExpiredRequests());
        assertFalse(requests.existsById(id));
    }

    private VaultAccessRequestService at(Instant instant) {
        return new VaultAccessRequestService(
                requests, validator, Clock.fixed(instant, ZoneOffset.UTC));
    }

    private static VaultAccessCreateRequest request(String id) {
        return new VaultAccessCreateRequest(
                id, "https://vault.example", DefaultCryptoService.DEVICE_KEY_ALGORITHM, "YWJj");
    }

    private static VaultAccessApprovalRequest approval() {
        return new VaultAccessApprovalRequest(
                "fp", "key", "TINK_DEVICE_KEY_PACKAGE", "wrapped-key");
    }

    private static void await(CountDownLatch latch) {
        try {
            assertTrue(
                    latch.await(5, TimeUnit.SECONDS), "Timed out waiting for transaction barrier");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError(e);
        }
    }
}
