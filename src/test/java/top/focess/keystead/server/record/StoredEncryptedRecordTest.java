package top.focess.keystead.server.record;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class StoredEncryptedRecordTest {

    private static final Instant UPDATED_AT = Instant.parse("2026-07-09T00:00:00Z");

    @Test
    void rejectsNonPositiveRevision() {
        assertThrows(IllegalArgumentException.class, () -> activeRecord("profile", "envelope", 0L));
    }

    @Test
    void activeRowRejectsMissingEncryptedProfile() {
        assertThrows(IllegalArgumentException.class, () -> activeRecord("", "envelope", 1L));
    }

    @Test
    void activeRowRejectsMissingEnvelope() {
        assertThrows(IllegalArgumentException.class, () -> activeRecord("profile", "", 1L));
    }

    @Test
    void tombstoneRejectsEncryptedProfileOrEnvelope() {
        assertThrows(IllegalArgumentException.class, () -> deletedRecord("profile", "", 1L));
        assertThrows(IllegalArgumentException.class, () -> deletedRecord("", "envelope", 1L));
    }

    @Test
    void rejectsUnsupportedSecretType() {
        assertThrows(
                IllegalArgumentException.class,
                () -> activeRecord("profile", "envelope", 1L, "PLAINTEXT_PASSWORD"));
    }

    private static StoredEncryptedRecord activeRecord(
            String encryptedProfile, String envelope, long revision) {
        return activeRecord(encryptedProfile, envelope, revision, "API_TOKEN");
    }

    private static StoredEncryptedRecord activeRecord(
            String encryptedProfile, String envelope, long revision, String secretType) {
        return new StoredEncryptedRecord(
                "alice",
                "vault-a",
                "secret-a",
                revision,
                secretType,
                encryptedProfile,
                encryptedProfile,
                envelope,
                false,
                UPDATED_AT);
    }

    private static StoredEncryptedRecord deletedRecord(
            String encryptedProfile, String envelope, long revision) {
        return new StoredEncryptedRecord(
                "alice",
                "vault-a",
                "secret-a",
                revision,
                "API_TOKEN",
                encryptedProfile,
                encryptedProfile,
                envelope,
                true,
                UPDATED_AT);
    }
}
