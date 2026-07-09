package top.focess.keystead.server.crypto;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

record CryptoAlgorithmCatalogResponse(
        @NonNull CryptoAlgorithmDefaultsResponse defaults,
        @NonNull List<String> payloadAeadAlgorithms,
        @NonNull List<String> vaultKeyKdfAlgorithms,
        @NonNull List<String> deviceProofAlgorithms,
        @NonNull List<String> vaultKeyPackageAlgorithms) {

    CryptoAlgorithmCatalogResponse {
        Objects.requireNonNull(defaults, "defaults");
        payloadAeadAlgorithms = validateAlgorithms(payloadAeadAlgorithms, "payloadAeadAlgorithms");
        vaultKeyKdfAlgorithms = validateAlgorithms(vaultKeyKdfAlgorithms, "vaultKeyKdfAlgorithms");
        deviceProofAlgorithms = validateAlgorithms(deviceProofAlgorithms, "deviceProofAlgorithms");
        vaultKeyPackageAlgorithms =
                validateAlgorithms(vaultKeyPackageAlgorithms, "vaultKeyPackageAlgorithms");
        requireDefault(payloadAeadAlgorithms, defaults.payloadAead(), "defaults.payloadAead");
        requireDefault(vaultKeyKdfAlgorithms, defaults.vaultKeyKdf(), "defaults.vaultKeyKdf");
        requireDefault(
                vaultKeyPackageAlgorithms, defaults.vaultKeyPackage(), "defaults.vaultKeyPackage");
    }

    static @NonNull CryptoAlgorithmCatalogResponse fromRegistry() {
        return new CryptoAlgorithmCatalogResponse(
                new CryptoAlgorithmDefaultsResponse(
                        ServerCryptoAlgorithmRegistry.PAYLOAD_AEAD_AES_256_GCM,
                        ServerCryptoAlgorithmRegistry.KDF_PBKDF2_HMAC_SHA256,
                        ServerCryptoAlgorithmRegistry
                                .DEVICE_TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM),
                ServerCryptoAlgorithmRegistry.approvedPayloadAeadAlgorithms(),
                ServerCryptoAlgorithmRegistry.approvedVaultKeyKdfAlgorithms(),
                ServerCryptoAlgorithmRegistry.approvedDeviceProofAlgorithms(),
                ServerCryptoAlgorithmRegistry.approvedVaultKeyPackageAlgorithms());
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
