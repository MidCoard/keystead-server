package top.focess.keystead.server.crypto;

import java.util.List;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.crypto.CryptoAlgorithmRegistry;

public final class ServerCryptoAlgorithmRegistry {

    public static final @NonNull String PAYLOAD_AEAD_AES_256_GCM =
            CryptoAlgorithmRegistry.AEAD_AES_256_GCM;
    public static final @NonNull String KDF_ARGON2ID = CryptoAlgorithmRegistry.KDF_ARGON2ID;
    public static final @NonNull String VAULT_ACCESS_EXCHANGE_KEY =
            CryptoAlgorithmRegistry.DEVICE_TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM;
    public static final @NonNull String VAULT_ACCESS_WRAPPED_KEY =
            CryptoAlgorithmRegistry.DEVICE_TINK_DEVICE_KEY_PACKAGE;

    private ServerCryptoAlgorithmRegistry() {}

    public static boolean isApprovedVaultAccessExchangeKeyAlgorithm(@NonNull String algorithm) {
        return VAULT_ACCESS_EXCHANGE_KEY.equals(algorithm);
    }

    public static boolean isApprovedVaultAccessWrappedKeyAlgorithm(@NonNull String algorithm) {
        return VAULT_ACCESS_WRAPPED_KEY.equals(algorithm);
    }

    public static @NonNull List<String> approvedPayloadAeadAlgorithms() {
        return CryptoAlgorithmRegistry.approvedAeadAlgorithms();
    }

    public static @NonNull List<String> approvedVaultKeyKdfAlgorithms() {
        return CryptoAlgorithmRegistry.approvedKdfAlgorithms();
    }

    public static @NonNull List<String> approvedVaultAccessExchangeKeyAlgorithms() {
        return List.of(VAULT_ACCESS_EXCHANGE_KEY);
    }

    public static @NonNull List<String> approvedVaultAccessWrappedKeyAlgorithms() {
        return List.of(VAULT_ACCESS_WRAPPED_KEY);
    }
}
