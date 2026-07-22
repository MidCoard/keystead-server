package top.focess.keystead.server.crypto;

import java.util.ArrayList;
import java.util.List;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.crypto.CryptoAlgorithmRegistry;

public final class ServerCryptoAlgorithmRegistry {

    public static final @NonNull String PAYLOAD_AEAD_AES_256_GCM =
            CryptoAlgorithmRegistry.AEAD_AES_256_GCM;
    public static final @NonNull String PAYLOAD_AEAD_CHACHA20_POLY1305 =
            CryptoAlgorithmRegistry.AEAD_CHACHA20_POLY1305;

    public static final @NonNull String KDF_PBKDF2_HMAC_SHA256 =
            CryptoAlgorithmRegistry.KDF_PBKDF2_HMAC_SHA256;
    public static final @NonNull String KDF_PBKDF2_HMAC_SHA512 =
            CryptoAlgorithmRegistry.KDF_PBKDF2_HMAC_SHA512;

    public static final @NonNull String DEVICE_RSA_OAEP_SHA256 = "RSA_OAEP_SHA256";
    public static final @NonNull String DEVICE_RSA_PSS_SHA256 = "RSA_PSS_SHA256";
    public static final @NonNull String DEVICE_ECDSA_P256_SHA256 = "ECDSA_P256_SHA256";
    public static final @NonNull String DEVICE_ECDSA_P384_SHA384 = "ECDSA_P384_SHA384";
    public static final @NonNull String DEVICE_ECDSA_P521_SHA512 = "ECDSA_P521_SHA512";
    public static final @NonNull String DEVICE_ED25519 = "ED25519";
    public static final @NonNull String DEVICE_TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM =
            CryptoAlgorithmRegistry.DEVICE_TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM;
    public static final @NonNull String DEVICE_TINK_DEVICE_KEY_PACKAGE =
            CryptoAlgorithmRegistry.DEVICE_TINK_DEVICE_KEY_PACKAGE;

    private static final List<String> PAYLOAD_AEAD_ALGORITHMS =
            CryptoAlgorithmRegistry.approvedAeadAlgorithms();
    private static final List<String> VAULT_KEY_KDF_ALGORITHMS =
            CryptoAlgorithmRegistry.approvedKdfAlgorithms();
    private static final List<String> DEVICE_PROOF_ALGORITHMS =
            List.of(
                    DEVICE_RSA_OAEP_SHA256,
                    DEVICE_RSA_PSS_SHA256,
                    DEVICE_ECDSA_P256_SHA256,
                    DEVICE_ECDSA_P384_SHA384,
                    DEVICE_ECDSA_P521_SHA512,
                    DEVICE_ED25519);

    private static final List<String> DEVICE_WRAPPING_PUBLIC_KEY_ALGORITHMS =
            List.of(DEVICE_RSA_OAEP_SHA256, DEVICE_TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM);

    private static final List<String> VAULT_KEY_PACKAGE_ALGORITHMS = vaultKeyPackageAlgorithms();

    private ServerCryptoAlgorithmRegistry() {}

    public static boolean isApprovedDeviceProofAlgorithm(@NonNull String algorithm) {
        return DEVICE_PROOF_ALGORITHMS.contains(algorithm);
    }

    public static boolean isApprovedVaultKeyPackageAlgorithm(@NonNull String algorithm) {
        return VAULT_KEY_PACKAGE_ALGORITHMS.contains(algorithm);
    }

    public static boolean isApprovedDeviceWrappingPublicKeyAlgorithm(@NonNull String algorithm) {
        return DEVICE_WRAPPING_PUBLIC_KEY_ALGORITHMS.contains(algorithm);
    }

    public static @NonNull List<String> approvedPayloadAeadAlgorithms() {
        return PAYLOAD_AEAD_ALGORITHMS;
    }

    public static @NonNull List<String> approvedVaultKeyKdfAlgorithms() {
        return VAULT_KEY_KDF_ALGORITHMS;
    }

    public static @NonNull List<String> approvedDeviceProofAlgorithms() {
        return DEVICE_PROOF_ALGORITHMS;
    }

    public static @NonNull List<String> approvedDeviceWrappingPublicKeyAlgorithms() {
        return DEVICE_WRAPPING_PUBLIC_KEY_ALGORITHMS;
    }

    public static @NonNull List<String> approvedVaultKeyPackageAlgorithms() {
        return VAULT_KEY_PACKAGE_ALGORITHMS;
    }

    private static @NonNull List<String> vaultKeyPackageAlgorithms() {
        List<String> algorithms = new ArrayList<>();
        algorithms.add(DEVICE_RSA_OAEP_SHA256);
        algorithms.addAll(CryptoAlgorithmRegistry.approvedDeviceKeyPackageAlgorithms());
        return List.copyOf(algorithms);
    }
}
