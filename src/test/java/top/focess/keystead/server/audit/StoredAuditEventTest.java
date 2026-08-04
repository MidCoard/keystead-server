package top.focess.keystead.server.audit;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class StoredAuditEventTest {

    private static final Instant CREATED_AT = Instant.parse("2026-07-09T00:00:00Z");

    @Test
    void recordEventsRequirePersonalVaultFingerprintAndRevision() {
        assertThrows(IllegalArgumentException.class, () -> record(null, 1L, "SUCCESS", "{}"));
        assertThrows(
                IllegalArgumentException.class, () -> record("vault-a", null, "SUCCESS", "{}"));
        assertThrows(IllegalArgumentException.class, () -> record("vault-a", 0L, "SUCCESS", "{}"));
    }

    @Test
    void loginFailureCannotPretendToBeARecordEvent() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredAuditEvent(
                                "event-a",
                                "alice",
                                "alice",
                                AuditEventType.LOGIN_FAILED.name(),
                                "record",
                                "alice",
                                null,
                                null,
                                "FAILURE",
                                "{}",
                                CREATED_AT));
    }

    @Test
    void sensitiveCiphertextAndCredentialFieldsAreRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () -> record("vault-a", 1L, "SUCCESS", "{\"envelope\":\"leak\"}"));
        assertThrows(
                IllegalArgumentException.class,
                () -> record("vault-a", 1L, "SUCCESS", "{\"password\":\"leak\"}"));
        assertThrows(
                IllegalArgumentException.class,
                () -> record("vault-a", 1L, "SUCCESS", "{\"token\":\"leak\"}"));
    }

    @Test
    void detailsMustBeAJsonObject() {
        assertThrows(
                IllegalArgumentException.class, () -> record("vault-a", 1L, "SUCCESS", "not-json"));
        assertThrows(
                IllegalArgumentException.class, () -> record("vault-a", 1L, "SUCCESS", "[1,2,3]"));
    }

    private static StoredAuditEvent record(
            String fingerprint, Long revision, String outcome, String details) {
        return new StoredAuditEvent(
                "event-a",
                "alice",
                "alice",
                AuditEventType.RECORD_STORED.name(),
                "record",
                "secret-a",
                fingerprint,
                revision,
                outcome,
                details,
                CREATED_AT);
    }
}
