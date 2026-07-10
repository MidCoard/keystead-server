package top.focess.keystead.server.record;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class RevisionConflictExceptionTest {

    private static final Instant UPDATED_AT = Instant.parse("2026-07-10T00:00:00Z");

    @Test
    void rejectsBlankConflictIdentity() {
        assertThrows(
                IllegalArgumentException.class, () -> conflict(" ", "vault-a", "secret-a", 2L, 1L));
        assertThrows(
                IllegalArgumentException.class, () -> conflict("message", " ", "secret-a", 2L, 1L));
        assertThrows(
                IllegalArgumentException.class, () -> conflict("message", "vault-a", " ", 2L, 1L));
    }

    @Test
    void rejectsImpossibleConflictRevisions() {
        assertThrows(
                IllegalArgumentException.class,
                () -> conflict("message", "vault-a", "secret-a", 0L, 1L));
        assertThrows(
                IllegalArgumentException.class,
                () -> conflict("message", "vault-a", "secret-a", 2L, 0L));
        assertThrows(
                IllegalArgumentException.class,
                () -> conflict("message", "vault-a", "secret-a", 1L, 2L));
    }

    @Test
    void rejectsMissingServerUpdateTime() {
        assertThrows(
                NullPointerException.class,
                () ->
                        new RevisionConflictException(
                                "message", "vault-a", "secret-a", 2L, 1L, false, null));
    }

    private static RevisionConflictException conflict(
            String message,
            String vaultId,
            String secretId,
            long latestRevision,
            long rejectedRevision) {
        return new RevisionConflictException(
                message, vaultId, secretId, latestRevision, rejectedRevision, false, UPDATED_AT);
    }
}
