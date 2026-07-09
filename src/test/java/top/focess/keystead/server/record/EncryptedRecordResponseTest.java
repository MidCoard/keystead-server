package top.focess.keystead.server.record;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class EncryptedRecordResponseTest {

    private static final Instant UPDATED_AT = Instant.parse("2026-07-10T00:00:00Z");

    @Test
    void rejectsNonPositiveRevision() {
        assertThrows(
                IllegalArgumentException.class,
                () -> activeRecord("encrypted-profile", "envelope", 0L));
    }

    @Test
    void activeResponseRequiresEncryptedProfileAndEnvelope() {
        assertThrows(IllegalArgumentException.class, () -> activeRecord(null, "envelope", 1L));
        assertThrows(IllegalArgumentException.class, () -> activeRecord("", "envelope", 1L));
        assertThrows(
                IllegalArgumentException.class, () -> activeRecord("encrypted-profile", null, 1L));
        assertThrows(
                IllegalArgumentException.class, () -> activeRecord("encrypted-profile", "", 1L));
    }

    @Test
    void tombstoneResponseRejectsEncryptedProfileOrEnvelope() {
        assertThrows(
                IllegalArgumentException.class, () -> tombstoneRecord("encrypted-profile", null));
        assertThrows(IllegalArgumentException.class, () -> tombstoneRecord(null, "envelope"));
    }

    @Test
    void responseRejectsLegacyMetadataAlias() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedRecordResponse(
                                "vault-a",
                                "secret-a",
                                1L,
                                "API_TOKEN",
                                "metadata-alias",
                                "encrypted-profile",
                                "envelope",
                                false,
                                UPDATED_AT));
    }

    @Test
    void responseRejectsBlankIdentifiersAndUnsupportedSecretType() {
        assertThrows(
                IllegalArgumentException.class,
                () -> response(" ", "secret-a", "API_TOKEN", false));
        assertThrows(
                IllegalArgumentException.class, () -> response("vault-a", " ", "API_TOKEN", false));
        assertThrows(
                IllegalArgumentException.class,
                () -> response("vault-a", "secret-a", "PLAINTEXT_PASSWORD", false));
    }

    private static EncryptedRecordResponse activeRecord(
            String encryptedProfile, String envelope, long revision) {
        return new EncryptedRecordResponse(
                "vault-a",
                "secret-a",
                revision,
                "API_TOKEN",
                null,
                encryptedProfile,
                envelope,
                false,
                UPDATED_AT);
    }

    private static EncryptedRecordResponse tombstoneRecord(
            String encryptedProfile, String envelope) {
        return new EncryptedRecordResponse(
                "vault-a",
                "secret-a",
                1L,
                "API_TOKEN",
                null,
                encryptedProfile,
                envelope,
                true,
                UPDATED_AT);
    }

    private static EncryptedRecordResponse response(
            String vaultId, String secretId, String secretType, boolean deleted) {
        return new EncryptedRecordResponse(
                vaultId,
                secretId,
                1L,
                secretType,
                null,
                deleted ? null : "encrypted-profile",
                deleted ? null : "envelope",
                deleted,
                UPDATED_AT);
    }
}
