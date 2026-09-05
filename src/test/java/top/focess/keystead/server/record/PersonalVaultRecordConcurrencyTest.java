package top.focess.keystead.server.record;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;
import java.util.concurrent.*;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import top.focess.keystead.service.EncryptedSyncRecord;
import top.focess.keystead.service.SyncRecordEventId;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class PersonalVaultRecordConcurrencyTest {
    @Autowired private PersonalVaultRecordService service;
    @Autowired private PersonalVaultRepository vaults;
    @Autowired private MockMvc mvc;
    @Autowired private PlatformTransactionManager transactions;

    @Test
    void appendsCannotExposeAHigherCursorBeforeAnEarlierTransactionCommits() throws Exception {
        String owner = owner();
        service.append(owner, request("baseline", "fp"));
        try (var pool = Executors.newVirtualThreadPerTaskExecutor();
                var first =
                        holdTransaction(
                                pool, () -> service.append(owner, request("first", "fp")))) {
            var attempted = new CountDownLatch(1);
            var second =
                    pool.submit(
                            () -> {
                                attempted.countDown();
                                return service.append(owner, request("second", "fp"));
                            });
            await(attempted);
            assertBlocked(second);
            var pageDuringWrite = service.page(owner, 0, 10);
            assertEquals(1, pageDuringWrite.records().size());
            first.release();
            var firstRecord = first.result();
            var secondRecord = second.get(5, TimeUnit.SECONDS);
            assertTrue(firstRecord.serverSequence() < secondRecord.serverSequence());
            var remaining = service.page(owner, pageDuringWrite.highestSequence(), 10);
            assertEquals(
                    java.util.List.of("first", "second"),
                    remaining.records().stream()
                            .map(PersonalVaultRecordResponse::secretId)
                            .toList());
        }
    }

    @Test
    void firstAppendCannotReplaceAnotherTransactionsFingerprint() throws Exception {
        String owner = owner();
        try (var pool = Executors.newVirtualThreadPerTaskExecutor();
                var first =
                        holdTransaction(
                                pool, () -> service.append(owner, request("first", "fp-first")))) {
            var attempted = new CountDownLatch(1);
            var second =
                    pool.submit(
                            () -> {
                                attempted.countDown();
                                return service.append(owner, request("second", "fp-other"));
                            });
            await(attempted);
            assertBlocked(second);
            first.release();
            first.result();
            assertInstanceOf(
                    PersonalVaultFingerprintConflictException.class,
                    assertThrows(ExecutionException.class, () -> second.get(5, TimeUnit.SECONDS))
                            .getCause());
            assertEquals("fp-first", vaults.findById(owner).orElseThrow().fingerprint);
            assertEquals(1, service.page(owner, 0, 10).records().size());
        }
    }

    @Test
    void appendAfterLastRecordPurgeRetainsItsFingerprintBinding() throws Exception {
        String owner = owner();
        service.append(owner, request("only", "fp"));
        try (var pool = Executors.newVirtualThreadPerTaskExecutor();
                var purge =
                        holdTransaction(pool, () -> service.deleteRecordHistory(owner, "only"))) {
            var attempted = new CountDownLatch(1);
            var append =
                    pool.submit(
                            () -> {
                                attempted.countDown();
                                return service.append(owner, request("after-purge", "fp"));
                            });
            await(attempted);
            assertBlocked(append);
            purge.release();
            assertEquals(1, purge.result().deletedEvents());
            append.get(5, TimeUnit.SECONDS);
            assertEquals("fp", vaults.findById(owner).orElseThrow().fingerprint);
            assertThrows(
                    PersonalVaultFingerprintConflictException.class,
                    () -> service.append(owner, request("other-vault", "fp-other")));
            assertEquals(1, service.page(owner, 0, 10).records().size());
        }
    }

    @Test
    void concurrentRetriesReturnTheSameStoredEvent() throws Exception {
        String owner = owner();
        var record = request("same", "fp");
        try (var pool = Executors.newVirtualThreadPerTaskExecutor();
                var first = holdTransaction(pool, () -> service.append(owner, record))) {
            var attempted = new CountDownLatch(1);
            var retry =
                    pool.submit(
                            () -> {
                                attempted.countDown();
                                return service.append(owner, record);
                            });
            await(attempted);
            assertBlocked(retry);
            first.release();
            assertEquals(
                    first.result().serverSequence(),
                    retry.get(5, TimeUnit.SECONDS).serverSequence());
            assertEquals(1, service.page(owner, 0, 10).records().size());
        }
    }

    @Test
    void anUncommittedAppendDoesNotBlockAnotherAccount() throws Exception {
        String owner = owner();
        String other = owner();
        try (var pool = Executors.newVirtualThreadPerTaskExecutor();
                var first =
                        holdTransaction(
                                pool, () -> service.append(owner, request("first", "fp")))) {
            var otherAppend =
                    pool.submit(() -> service.append(other, request("other", "fp-other")));
            assertEquals("other", otherAppend.get(5, TimeUnit.SECONDS).secretId());
            first.release();
            first.result();
        }
    }

    private String owner() throws Exception {
        String owner = "concurrency-" + UUID.randomUUID();
        mvc.perform(
                        post("/api/v1/users")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        "{\"username\":\"%s\",\"password\":\"valid-test-password\"}"
                                                .formatted(owner)))
                .andExpect(status().isCreated());
        return owner;
    }

    private static PersonalVaultRecordRequest request(String id, String fingerprint) {
        var record =
                new EncryptedSyncRecord(
                        fingerprint,
                        id,
                        1,
                        "SECURE_NOTE",
                        "profile",
                        "envelope",
                        false,
                        "key-" + id);
        return new PersonalVaultRecordRequest(
                SyncRecordEventId.of(record),
                fingerprint,
                id,
                1,
                "SECURE_NOTE",
                "profile",
                "envelope",
                false,
                "key-" + id);
    }

    private <T> HeldTransaction<T> holdTransaction(ExecutorService pool, Supplier<T> action)
            throws Exception {
        var completedAction = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var future =
                pool.submit(
                        () ->
                                new TransactionTemplate(transactions)
                                        .execute(
                                                status -> {
                                                    try {
                                                        T value = action.get();
                                                        completedAction.countDown();
                                                        await(release);
                                                        return value;
                                                    } finally {
                                                        completedAction.countDown();
                                                    }
                                                }));
        await(completedAction);
        if (future.isDone()) {
            future.get(5, TimeUnit.SECONDS);
            fail("The transaction should still be held open");
        }
        return new HeldTransaction<>(future, release);
    }

    private static void assertBlocked(Future<?> future) {
        assertThrows(TimeoutException.class, () -> future.get(200, TimeUnit.MILLISECONDS));
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

    private record HeldTransaction<T>(Future<T> future, CountDownLatch barrier)
            implements AutoCloseable {
        void release() {
            barrier.countDown();
        }

        T result() throws Exception {
            return future.get(5, TimeUnit.SECONDS);
        }

        @Override
        public void close() {
            release();
        }
    }
}
