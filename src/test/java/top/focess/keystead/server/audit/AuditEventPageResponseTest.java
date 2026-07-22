package top.focess.keystead.server.audit;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class AuditEventPageResponseTest {

    private static final Instant CREATED_AT = Instant.parse("2026-07-09T00:00:00Z");

    private static AuditEventResponse event() {
        return new AuditEventResponse(
                "event-a",
                "alice",
                "actor-a",
                "RECORD_STORED",
                "record",
                "secret-a",
                "vault-a",
                1L,
                "SUCCESS",
                "{}",
                CREATED_AT,
                "correlation-a",
                null);
    }

    @Test
    void rejectsNonPositivePageLimit() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new AuditEventPageResponse(List.of(), 0, false, null, null));
        assertThrows(
                IllegalArgumentException.class,
                () -> new AuditEventPageResponse(List.of(), -1, false, null, null));
    }

    @Test
    void rejectsMissingCursorWhenMoreEventsExist() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new AuditEventPageResponse(List.of(event()), 10, true, null, null));
        assertThrows(
                IllegalArgumentException.class,
                () -> new AuditEventPageResponse(List.of(event()), 10, true, CREATED_AT, null));
        assertThrows(
                IllegalArgumentException.class,
                () -> new AuditEventPageResponse(List.of(event()), 10, true, null, "event-b"));
    }

    @Test
    void rejectsCursorWhenNoMoreEventsExist() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new AuditEventPageResponse(
                                List.of(event()), 10, false, CREATED_AT, "event-b"));
        assertThrows(
                IllegalArgumentException.class,
                () -> new AuditEventPageResponse(List.of(event()), 10, false, CREATED_AT, null));
        assertThrows(
                IllegalArgumentException.class,
                () -> new AuditEventPageResponse(List.of(event()), 10, false, null, "event-b"));
    }

    @Test
    void acceptsValidPages() {
        assertDoesNotThrow(
                () -> new AuditEventPageResponse(List.of(event()), 10, false, null, null));
        assertDoesNotThrow(
                () ->
                        new AuditEventPageResponse(
                                List.of(event()), 10, true, CREATED_AT, "event-b"));
        assertDoesNotThrow(() -> new AuditEventPageResponse(List.of(), 1, false, null, null));
    }
}
