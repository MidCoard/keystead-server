package top.focess.keystead.server.audit;

import static org.junit.jupiter.api.Assertions.assertNotNull;
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

    @Test
    void rejectsUnsupportedTargetType() {
        assertThrows(IllegalArgumentException.class, () -> eventWithTargetType("plaintext"));
    }

    @Test
    void rejectsRecordEventsWithoutVaultAndRevision() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        event(
                                AuditEventType.RECORD_STORED,
                                "record",
                                "secret-a",
                                null,
                                1L,
                                "SUCCESS"));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        event(
                                AuditEventType.RECORD_STORED,
                                "record",
                                "secret-a",
                                "vault-a",
                                null,
                                "SUCCESS"));
    }

    @Test
    void rejectsEventTypeTargetMismatches() {
        assertThrows(
                IllegalArgumentException.class,
                () -> event(AuditEventType.LOGIN_FAILED, "record", "alice", null, null, "FAILURE"));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        event(
                                AuditEventType.DEVICE_REVOKED,
                                "key_package",
                                "device-a",
                                null,
                                null,
                                "SUCCESS"));
    }

    @Test
    void rejectsEventTypeOutcomeMismatches() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        event(
                                AuditEventType.RECORD_REVISION_CONFLICT,
                                "record",
                                "secret-a",
                                "vault-a",
                                1L,
                                "SUCCESS"));
        assertThrows(
                IllegalArgumentException.class,
                () -> event(AuditEventType.LOGIN_FAILED, "auth", "alice", null, null, "SUCCESS"));
    }

    @Test
    void rejectsNonRecordEventsWithVaultOrRevision() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        event(
                                AuditEventType.LOGIN_FAILED,
                                "auth",
                                "alice",
                                "vault-a",
                                null,
                                "FAILURE"));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        event(
                                AuditEventType.DEVICE_REVOKED,
                                "device",
                                "device-a",
                                null,
                                1L,
                                "SUCCESS"));
    }

    @Test
    void rejectsDetailsThatAreNotJsonObjects() {
        assertThrows(
                IllegalArgumentException.class,
                () -> event("event-a", "alice", "SUCCESS", "not-json"));
    }

    @Test
    void rejectsDetailsThatAreValidJsonButNotObjects() {
        assertThrows(
                IllegalArgumentException.class,
                () -> event("event-a", "alice", "SUCCESS", "[1, 2, 3]"));
        assertThrows(
                IllegalArgumentException.class, () -> event("event-a", "alice", "SUCCESS", "42"));
    }

    @Test
    void rejectsBlankVaultIdWhenPresent() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        event(
                                AuditEventType.RECORD_STORED,
                                "record",
                                "secret-a",
                                " ",
                                1L,
                                "SUCCESS"));
    }

    @Test
    void rejectsForbiddenSensitiveDetailKeys() {
        assertThrows(
                IllegalArgumentException.class,
                () -> event("event-a", "alice", "SUCCESS", "{\"encryptedProfile\":\"leak\"}"));
        assertThrows(
                IllegalArgumentException.class,
                () -> event("event-a", "alice", "SUCCESS", "{\"envelope\":\"leak\"}"));
        assertThrows(
                IllegalArgumentException.class,
                () -> event("event-a", "alice", "SUCCESS", "{\"wrappedVaultKey\":\"leak\"}"));
        assertThrows(
                IllegalArgumentException.class,
                () -> event("event-a", "alice", "SUCCESS", "{\"password\":\"leak\"}"));
        assertThrows(
                IllegalArgumentException.class,
                () -> event("event-a", "alice", "SUCCESS", "{\"token\":\"leak\"}"));
    }

    @Test
    void rejectsForbiddenSensitiveDetailKeyAliases() {
        assertThrows(
                IllegalArgumentException.class,
                () -> event("event-a", "alice", "SUCCESS", "{\"encrypted_profile\":\"leak\"}"));
        assertThrows(
                IllegalArgumentException.class,
                () -> event("event-a", "alice", "SUCCESS", "{\"wrapped-vault-key\":\"leak\"}"));
        assertThrows(
                IllegalArgumentException.class,
                () -> event("event-a", "alice", "SUCCESS", "{\"REFRESH_TOKEN\":\"leak\"}"));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        event(
                                "event-a",
                                "alice",
                                "SUCCESS",
                                "{\"nested\":{\"device_private_key\":\"leak\"}}"));
    }

    @Test
    void acceptsAndRejectsVaultMemberEventShapes() {
        assertNotNull(
                event(
                        AuditEventType.VAULT_MEMBER_INVITED,
                        "vault_member",
                        "member-a",
                        "vault-a",
                        null,
                        "SUCCESS"));
        assertNotNull(
                event(
                        AuditEventType.VAULT_MEMBER_ACCEPTED,
                        "vault_member",
                        "member-a",
                        "vault-a",
                        null,
                        "SUCCESS"));
        assertNotNull(
                event(
                        AuditEventType.VAULT_MEMBER_DECLINED,
                        "vault_member",
                        "member-a",
                        "vault-a",
                        null,
                        "SUCCESS"));
        assertNotNull(
                event(
                        AuditEventType.VAULT_MEMBER_ROLE_CHANGED,
                        "vault_member",
                        "member-a",
                        "vault-a",
                        null,
                        "SUCCESS"));
        assertNotNull(
                event(
                        AuditEventType.VAULT_MEMBER_REMOVED,
                        "vault_member",
                        "member-a",
                        "vault-a",
                        null,
                        "SUCCESS"));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        event(
                                AuditEventType.VAULT_MEMBER_INVITED,
                                "record",
                                "member-a",
                                "vault-a",
                                null,
                                "SUCCESS"));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        event(
                                AuditEventType.VAULT_MEMBER_ACCEPTED,
                                "vault_member",
                                "member-a",
                                null,
                                null,
                                "SUCCESS"));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        event(
                                AuditEventType.VAULT_MEMBER_REMOVED,
                                "vault_member",
                                "member-a",
                                "vault-a",
                                1L,
                                "SUCCESS"));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        event(
                                AuditEventType.VAULT_MEMBER_ROLE_CHANGED,
                                "vault_member",
                                "member-a",
                                "vault-a",
                                null,
                                "FAILURE"));
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

    private static StoredAuditEvent event(
            AuditEventType eventType,
            String targetType,
            String targetId,
            String vaultId,
            Long revision,
            String outcome) {
        return new StoredAuditEvent(
                "event-a",
                "alice",
                "actor-a",
                eventType.name(),
                targetType,
                targetId,
                vaultId,
                revision,
                outcome,
                "{}",
                CREATED_AT);
    }

    private static StoredAuditEvent eventWithTargetType(String targetType) {
        return new StoredAuditEvent(
                "event-a",
                "alice",
                "actor-a",
                AuditEventType.RECORD_STORED.name(),
                targetType,
                "secret-a",
                "vault-a",
                1L,
                "SUCCESS",
                "{}",
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
