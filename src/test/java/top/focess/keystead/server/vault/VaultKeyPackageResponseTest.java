package top.focess.keystead.server.vault;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class VaultKeyPackageResponseTest {

    private static final Instant CREATED_AT = Instant.parse("2026-07-10T00:00:00Z");
    private static final Instant UPDATED_AT = Instant.parse("2026-07-10T00:01:00Z");
    private static final Instant BEFORE_CREATED_AT = Instant.parse("2026-07-09T23:59:59Z");

    @Test
    void rejectsBlankKeyPackageResponseFields() {
        assertThrows(
                IllegalArgumentException.class,
                () -> response(" ", "device-a", "RSA_OAEP_SHA256", "wrapped-key", UPDATED_AT));
        assertThrows(
                IllegalArgumentException.class,
                () -> response("vault-a", " ", "RSA_OAEP_SHA256", "wrapped-key", UPDATED_AT));
        assertThrows(
                IllegalArgumentException.class,
                () -> response("vault-a", "device-a", " ", "wrapped-key", UPDATED_AT));
        assertThrows(
                IllegalArgumentException.class,
                () -> response("vault-a", "device-a", "RSA_OAEP_SHA256", " ", UPDATED_AT));
    }

    @Test
    void rejectsUnsupportedKeyPackageAlgorithm() {
        assertThrows(
                IllegalArgumentException.class,
                () -> response("vault-a", "device-a", "RAW_RSA", "wrapped-key", UPDATED_AT));
    }

    @Test
    void rejectsUpdatedTimeBeforeCreatedTime() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        response(
                                "vault-a",
                                "device-a",
                                "RSA_OAEP_SHA256",
                                "wrapped-key",
                                BEFORE_CREATED_AT));
    }

    private static VaultKeyPackageResponse response(
            String vaultId,
            String deviceId,
            String keyAlgorithm,
            String encryptedVaultKey,
            Instant updatedAt) {
        return new VaultKeyPackageResponse(
                vaultId, deviceId, keyAlgorithm, encryptedVaultKey, CREATED_AT, updatedAt);
    }
}
