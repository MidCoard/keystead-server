package top.focess.keystead.server.crypto;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

record CryptoAlgorithmCatalogResponse(
        @NonNull CryptoAlgorithmDefaultsResponse defaults,
        @NonNull List<String> payloadAeadAlgorithms,
        @NonNull List<String> vaultKeyKdfAlgorithms,
        @NonNull List<String> vaultAccessExchangeKeyAlgorithms,
        @NonNull List<String> vaultAccessWrappedKeyAlgorithms) {

    CryptoAlgorithmCatalogResponse {
        Objects.requireNonNull(defaults, "defaults");
        payloadAeadAlgorithms = validateAlgorithms(payloadAeadAlgorithms, "payloadAeadAlgorithms");
        vaultKeyKdfAlgorithms = validateAlgorithms(vaultKeyKdfAlgorithms, "vaultKeyKdfAlgorithms");
        vaultAccessExchangeKeyAlgorithms =
                validateAlgorithms(
                        vaultAccessExchangeKeyAlgorithms, "vaultAccessExchangeKeyAlgorithms");
        vaultAccessWrappedKeyAlgorithms =
                validateAlgorithms(
                        vaultAccessWrappedKeyAlgorithms, "vaultAccessWrappedKeyAlgorithms");
        requireDefault(payloadAeadAlgorithms, defaults.payloadAead(), "defaults.payloadAead");
        requireDefault(vaultKeyKdfAlgorithms, defaults.vaultKeyKdf(), "defaults.vaultKeyKdf");
        requireDefault(
                vaultAccessExchangeKeyAlgorithms,
                defaults.vaultAccessExchangeKey(),
                "defaults.vaultAccessExchangeKey");
        requireDefault(
                vaultAccessWrappedKeyAlgorithms,
                defaults.vaultAccessWrappedKey(),
                "defaults.vaultAccessWrappedKey");
    }

    static @NonNull CryptoAlgorithmCatalogResponse fromRegistry() {
        return new CryptoAlgorithmCatalogResponse(
                new CryptoAlgorithmDefaultsResponse(
                        ServerCryptoAlgorithmRegistry.PAYLOAD_AEAD_AES_256_GCM,
                        ServerCryptoAlgorithmRegistry.KDF_ARGON2ID,
                        ServerCryptoAlgorithmRegistry.VAULT_ACCESS_EXCHANGE_KEY,
                        ServerCryptoAlgorithmRegistry.VAULT_ACCESS_WRAPPED_KEY),
                ServerCryptoAlgorithmRegistry.approvedPayloadAeadAlgorithms(),
                ServerCryptoAlgorithmRegistry.approvedVaultKeyKdfAlgorithms(),
                ServerCryptoAlgorithmRegistry.approvedVaultAccessExchangeKeyAlgorithms(),
                ServerCryptoAlgorithmRegistry.approvedVaultAccessWrappedKeyAlgorithms());
    }

    private static @NonNull List<String> validateAlgorithms(
            @NonNull List<String> algorithms, @NonNull String field) {
        List<String> snapshot = List.copyOf(Objects.requireNonNull(algorithms, field));
        if (snapshot.isEmpty()) {
            throw new IllegalArgumentException(field + " must not be empty");
        }
        LinkedHashSet<String> unique = new LinkedHashSet<>();
        for (String algorithm : snapshot) {
            Objects.requireNonNull(algorithm, field + " entry");
            if (algorithm.isBlank()) {
                throw new IllegalArgumentException(field + " entries must not be blank");
            }
            if (!unique.add(algorithm)) {
                throw new IllegalArgumentException(field + " entries must be unique");
            }
        }
        return snapshot;
    }

    private static void requireDefault(
            @NonNull List<String> algorithms,
            @NonNull String defaultAlgorithm,
            @NonNull String field) {
        if (!algorithms.contains(defaultAlgorithm)) {
            throw new IllegalArgumentException(field + " must be listed in the catalog");
        }
    }
}
