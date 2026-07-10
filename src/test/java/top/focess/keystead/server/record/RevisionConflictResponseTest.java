package top.focess.keystead.server.record;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class RevisionConflictResponseTest {

    private static final Instant UPDATED_AT = Instant.parse("2026-07-10T00:00:00Z");

    @Test
    void rejectsBlankConflictIdentity() {
        assertThrows(
                IllegalArgumentException.class,
                () -> response(" ", "message", "vault-a", "secret-a", 2L, 1L));
        assertThrows(
                IllegalArgumentException.class,
                () -> response("REVISION_CONFLICT", " ", "vault-a", "secret-a", 2L, 1L));
        assertThrows(
                IllegalArgumentException.class,
                () -> response("REVISION_CONFLICT", "message", " ", "secret-a", 2L, 1L));
        assertThrows(
                IllegalArgumentException.class,
                () -> response("REVISION_CONFLICT", "message", "vault-a", " ", 2L, 1L));
    }

    @Test
    void rejectsImpossibleConflictRevisions() {
        assertThrows(
                IllegalArgumentException.class,
                () -> response("REVISION_CONFLICT", "message", "vault-a", "secret-a", 0L, 1L));
        assertThrows(
                IllegalArgumentException.class,
                () -> response("REVISION_CONFLICT", "message", "vault-a", "secret-a", 2L, 0L));
        assertThrows(
                IllegalArgumentException.class,
                () -> response("REVISION_CONFLICT", "message", "vault-a", "secret-a", 1L, 2L));
    }

    @Test
    void rejectsMissingServerUpdateTime() {
        assertThrows(
                NullPointerException.class,
                () ->
                        new RevisionConflictResponse(
                                "REVISION_CONFLICT",
                                "message",
                                "vault-a",
                                "secret-a",
                                2L,
                                1L,
                                2L,
                                1L,
                                false,
                                null));
    }

    private static RevisionConflictResponse response(
            String code,
            String message,
            String vaultId,
            String secretId,
            long serverRevision,
            long clientRevision) {
        return new RevisionConflictResponse(
                code,
                message,
                vaultId,
                secretId,
                serverRevision,
                clientRevision,
                serverRevision,
                clientRevision,
                false,
                UPDATED_AT);
    }
}
