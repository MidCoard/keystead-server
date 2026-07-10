package top.focess.keystead.server.record;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class EncryptedRecordRequestTest {

    @Test
    void rejectsUnsupportedSecretType() {
        assertThrows(
                InvalidRecordRequestException.class,
                () -> active("OAUTH_REFRESH_TOKEN", "profile", "envelope").validateShape());
    }

    @Test
    void rejectsActiveRecordWithoutEncryptedFields() {
        assertThrows(
                InvalidRecordRequestException.class,
                () -> active("API_TOKEN", " ", "envelope").validateShape());
        assertThrows(
                InvalidRecordRequestException.class,
                () -> active("API_TOKEN", "profile", " ").validateShape());
    }

    @Test
    void rejectsActiveRecordWithConflictingMetadataAlias() {
        assertThrows(
                InvalidRecordRequestException.class,
                () ->
                        new EncryptedRecordRequest(
                                        1L,
                                        "API_TOKEN",
                                        "legacy-profile",
                                        "canonical-profile",
                                        "envelope",
                                        false)
                                .validateShape());
    }

    @Test
    void rejectsTombstoneWithEncryptedFields() {
        assertThrows(
                InvalidRecordRequestException.class,
                () -> tombstone("API_TOKEN", "profile", null, null).validateShape());
        assertThrows(
                InvalidRecordRequestException.class,
                () -> tombstone("API_TOKEN", null, "profile", null).validateShape());
        assertThrows(
                InvalidRecordRequestException.class,
                () -> tombstone("API_TOKEN", null, null, "envelope").validateShape());
    }

    private static EncryptedRecordRequest active(
            String secretType, String encryptedProfile, String envelope) {
        return new EncryptedRecordRequest(1L, secretType, null, encryptedProfile, envelope, false);
    }

    private static EncryptedRecordRequest tombstone(
            String secretType, String metadata, String encryptedProfile, String envelope) {
        return new EncryptedRecordRequest(
                1L, secretType, metadata, encryptedProfile, envelope, true);
    }
}
