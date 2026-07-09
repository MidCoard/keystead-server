package top.focess.keystead.server.record;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class EncryptedRecordPageResponseTest {

    private static final Instant UPDATED_AT = Instant.parse("2026-07-10T00:00:00Z");

    @Test
    void rejectsStalledPageCursor() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedRecordPageResponse(
                                "vault-a",
                                1L,
                                List.of(record("vault-a", "secret-a", 2L)),
                                2L,
                                true,
                                null));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedRecordPageResponse(
                                "vault-a",
                                1L,
                                List.of(record("vault-a", "secret-a", 2L)),
                                2L,
                                true,
                                1L));
    }

    @Test
    void rejectsHighestRevisionThatDoesNotMatchReturnedRows() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedRecordPageResponse(
                                "vault-a",
                                1L,
                                List.of(record("vault-a", "secret-a", 2L)),
                                3L,
                                false,
                                null));
        assertThrows(
                IllegalArgumentException.class,
                () -> new EncryptedRecordPageResponse("vault-a", 1L, List.of(), 2L, false, null));
    }

    @Test
    void rejectsRowsOutsidePageVaultOrCursor() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedRecordPageResponse(
                                "vault-a",
                                1L,
                                List.of(record("vault-b", "secret-a", 2L)),
                                2L,
                                false,
                                null));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedRecordPageResponse(
                                "vault-a",
                                1L,
                                List.of(record("vault-a", "secret-a", 1L)),
                                1L,
                                false,
                                null));
    }

    @Test
    void snapshotsReturnedRecordList() {
        List<EncryptedRecordResponse> records = new ArrayList<>();
        records.add(record("vault-a", "secret-a", 2L));

        EncryptedRecordPageResponse page =
                new EncryptedRecordPageResponse("vault-a", 1L, records, 2L, false, null);
        records.clear();

        assertEquals(1, page.records().size());
        assertThrows(UnsupportedOperationException.class, () -> page.records().clear());
    }

    private static EncryptedRecordResponse record(String vaultId, String secretId, long revision) {
        return new EncryptedRecordResponse(
                vaultId,
                secretId,
                revision,
                "API_TOKEN",
                null,
                "encrypted-profile",
                "envelope",
                false,
                UPDATED_AT);
    }
}
