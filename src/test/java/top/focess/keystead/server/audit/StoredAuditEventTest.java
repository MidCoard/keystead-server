package top.focess.keystead.server.audit;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class StoredAuditEventTest {

    private static final Instant CREATED_AT = Instant.parse("2026-07-09T00:00:00Z");

    @Test
    void rejectsBlankRequiredClassifierFields() {
        assertThrows(IllegalArgumentException.class, () -> event(" ", "alice", "SUCCESS", "{}"));
        assertThrows(IllegalArgumentException.class, () -> event("event-a", " ", "SUCCESS", "{}"));
        assertThrows(IllegalArgumentException.class, () -> event("event-a", "alice", " ", "{}"));
        assertThrows(
                IllegalArgumentException.class, () -> event("event-a", "alice", "SUCCESS", " "));
    }

    @Test
    void rejectsNonPositiveRevisionWhenPresent() {
        assertThrows(IllegalArgumentException.class, () -> eventWithRevision(0L));
    }

    @Test
    void rejectsUnsupportedOutcome() {
        assertThrows(
                IllegalArgumentException.class, () -> event("event-a", "alice", "LEAKED", "{}"));
    }

    @Test
    void rejectsUnsupportedEventType() {
        assertThrows(IllegalArgumentException.class, () -> eventWithType("SECRET_EXFILTRATED"));
    }

    private static StoredAuditEvent event(
            String eventId, String ownerId, String outcome, String details) {
        return new StoredAuditEvent(
                eventId,
                ownerId,
                "actor-a",
                AuditEventType.RECORD_STORED.name(),
                "record",
                "secret-a",
                "vault-a",
                1L,
                outcome,
                details,
                CREATED_AT);
    }

    private static StoredAuditEvent eventWithType(String eventType) {
        return new StoredAuditEvent(
                "event-a",
                "alice",
                "actor-a",
                eventType,
                "record",
                "secret-a",
                "vault-a",
                1L,
                "SUCCESS",
                "{}",
                CREATED_AT);
    }

    private static StoredAuditEvent eventWithRevision(Long revision) {
        return new StoredAuditEvent(
                "event-a",
                "alice",
                "actor-a",
                AuditEventType.RECORD_STORED.name(),
                "record",
                "secret-a",
                "vault-a",
                revision,
                "SUCCESS",
                "{}",
                CREATED_AT);
    }
}
