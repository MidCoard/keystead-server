package top.focess.keystead.server.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class CryptoAlgorithmCatalogResponseTest {

    @Test
    void rejectsBlankDefaultAlgorithms() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new CryptoAlgorithmDefaultsResponse(
                                " ", "PBKDF2WithHmacSHA256", "RSA_OAEP_SHA256"));
        assertThrows(
                IllegalArgumentException.class,
                () -> new CryptoAlgorithmDefaultsResponse("AES-256-GCM", " ", "RSA_OAEP_SHA256"));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new CryptoAlgorithmDefaultsResponse(
                                "AES-256-GCM", "PBKDF2WithHmacSHA256", " "));
    }

    @Test
    void rejectsEmptyCatalogLists() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        catalog(
                                List.of(),
                                List.of("PBKDF2WithHmacSHA256"),
                                List.of("RSA_PSS_SHA256"),
                                List.of("RSA_OAEP_SHA256"),
                                defaults()));
    }

    @Test
    void rejectsBlankAndDuplicateCatalogAlgorithms() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        catalog(
                                List.of("AES-256-GCM", " "),
                                List.of("PBKDF2WithHmacSHA256"),
                                List.of("RSA_PSS_SHA256"),
                                List.of("RSA_OAEP_SHA256"),
                                defaults()));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        catalog(
                                List.of("AES-256-GCM", "AES-256-GCM"),
                                List.of("PBKDF2WithHmacSHA256"),
                                List.of("RSA_PSS_SHA256"),
                                List.of("RSA_OAEP_SHA256"),
                                defaults()));
    }

    @Test
    void rejectsDefaultsOutsideCatalogLists() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        catalog(
                                List.of("CHACHA20-POLY1305"),
                                List.of("PBKDF2WithHmacSHA256"),
                                List.of("RSA_PSS_SHA256"),
                                List.of("RSA_OAEP_SHA256"),
                                defaults()));
    }

    @Test
    void snapshotsCatalogLists() {
        List<String> payloadAlgorithms = new ArrayList<>(List.of("AES-256-GCM"));
        CryptoAlgorithmCatalogResponse response =
                catalog(
                        payloadAlgorithms,
                        List.of("PBKDF2WithHmacSHA256"),
                        List.of("RSA_PSS_SHA256"),
                        List.of("RSA_OAEP_SHA256"),
                        defaults());

        payloadAlgorithms.add("CHACHA20-POLY1305");

        assertEquals(List.of("AES-256-GCM"), response.payloadAeadAlgorithms());
        assertThrows(
                UnsupportedOperationException.class,
                () -> response.payloadAeadAlgorithms().add("CHACHA20-POLY1305"));
    }

    private static CryptoAlgorithmCatalogResponse catalog(
            List<String> payloadAeadAlgorithms,
            List<String> vaultKeyKdfAlgorithms,
            List<String> deviceProofAlgorithms,
            List<String> vaultKeyPackageAlgorithms,
            CryptoAlgorithmDefaultsResponse defaults) {
        return new CryptoAlgorithmCatalogResponse(
                defaults,
                payloadAeadAlgorithms,
                vaultKeyKdfAlgorithms,
                deviceProofAlgorithms,
                vaultKeyPackageAlgorithms);
    }

    private static CryptoAlgorithmDefaultsResponse defaults() {
        return new CryptoAlgorithmDefaultsResponse(
                "AES-256-GCM", "PBKDF2WithHmacSHA256", "RSA_OAEP_SHA256");
    }
}
