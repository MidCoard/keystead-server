package top.focess.keystead.server.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class CryptoAlgorithmCatalogResponseTest {

    @Test
    void rejectsBlankDefaultsAndMissingDefaultAlgorithms() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new CryptoAlgorithmDefaultsResponse(" ", "ARGON2ID", "exchange", "wrapped"));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new CryptoAlgorithmCatalogResponse(
                                defaults(),
                                List.of("CHACHA20-POLY1305"),
                                List.of("ARGON2ID"),
                                List.of("exchange"),
                                List.of("wrapped")));
    }

    @Test
    void rejectsEmptyBlankAndDuplicateCatalogLists() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        catalog(
                                List.of(),
                                List.of("ARGON2ID"),
                                List.of("exchange"),
                                List.of("wrapped")));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        catalog(
                                List.of("AES-256-GCM", " "),
                                List.of("ARGON2ID"),
                                List.of("exchange"),
                                List.of("wrapped")));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        catalog(
                                List.of("AES-256-GCM", "AES-256-GCM"),
                                List.of("ARGON2ID"),
                                List.of("exchange"),
                                List.of("wrapped")));
    }

    @Test
    void snapshotsCatalogLists() {
        List<String> payloadAlgorithms = new ArrayList<>(List.of("AES-256-GCM"));
        CryptoAlgorithmCatalogResponse response =
                catalog(
                        payloadAlgorithms,
                        List.of("ARGON2ID"),
                        List.of("exchange"),
                        List.of("wrapped"));

        payloadAlgorithms.add("CHACHA20-POLY1305");

        assertEquals(List.of("AES-256-GCM"), response.payloadAeadAlgorithms());
        assertThrows(
                UnsupportedOperationException.class,
                () -> response.payloadAeadAlgorithms().add("CHACHA20-POLY1305"));
    }

    private static CryptoAlgorithmCatalogResponse catalog(
            List<String> payloadAeadAlgorithms,
            List<String> vaultKeyKdfAlgorithms,
            List<String> exchangeAlgorithms,
            List<String> wrappedAlgorithms) {
        return new CryptoAlgorithmCatalogResponse(
                defaults(),
                payloadAeadAlgorithms,
                vaultKeyKdfAlgorithms,
                exchangeAlgorithms,
                wrappedAlgorithms);
    }

    private static CryptoAlgorithmDefaultsResponse defaults() {
        return new CryptoAlgorithmDefaultsResponse(
                "AES-256-GCM", "ARGON2ID", "exchange", "wrapped");
    }
}
