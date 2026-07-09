package top.focess.keystead.server.vault;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class VaultKeyPackageRequestTest {

    @Test
    void rejectsUnsupportedKeyPackageAlgorithm() {
        assertThrows(
                InvalidVaultKeyPackageRequestException.class,
                () -> request("RAW_RSA", "wrapped-key").validateShape());
    }

    @Test
    void rejectsBlankOpaqueKeyPackageFields() {
        assertThrows(
                InvalidVaultKeyPackageRequestException.class,
                () -> request(" ", "wrapped-key").validateShape());
        assertThrows(
                InvalidVaultKeyPackageRequestException.class,
                () -> request("RSA_OAEP_SHA256", " ").validateShape());
    }

    private static VaultKeyPackageRequest request(String keyAlgorithm, String encryptedVaultKey) {
        return new VaultKeyPackageRequest(keyAlgorithm, encryptedVaultKey);
    }
}
