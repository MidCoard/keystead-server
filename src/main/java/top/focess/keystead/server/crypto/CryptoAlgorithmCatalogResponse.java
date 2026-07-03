package top.focess.keystead.server.crypto;

import java.util.List;
import org.jspecify.annotations.NonNull;

record CryptoAlgorithmCatalogResponse(
        @NonNull CryptoAlgorithmDefaultsResponse defaults,
        @NonNull List<String> payloadAeadAlgorithms,
        @NonNull List<String> vaultKeyKdfAlgorithms,
        @NonNull List<String> deviceProofAlgorithms,
        @NonNull List<String> vaultKeyPackageAlgorithms) {

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
}
