package top.focess.keystead.server.identity;

import java.util.Arrays;
import java.util.Base64;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.server.crypto.ServerCryptoAlgorithmRegistry;

final class DeviceKeyMaterial {

    private DeviceKeyMaterial() {}

    static boolean cannotProveSeparation(
            @NonNull String proofKeyAlgorithm,
            @NonNull String proofPublicKey,
            @NonNull String wrappingKeyAlgorithm,
            @NonNull String wrappingPublicKey) {
        return isAmbiguousP256Pair(proofKeyAlgorithm, wrappingKeyAlgorithm)
                || samePublicKey(proofPublicKey, wrappingPublicKey);
    }

    private static boolean isAmbiguousP256Pair(
            @NonNull String proofKeyAlgorithm, @NonNull String wrappingKeyAlgorithm) {
        return ServerCryptoAlgorithmRegistry.DEVICE_ECDSA_P256_SHA256.equals(proofKeyAlgorithm)
                && ServerCryptoAlgorithmRegistry.DEVICE_TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
                        .equals(wrappingKeyAlgorithm);
    }

    private static boolean samePublicKey(
            @NonNull String proofPublicKey, @NonNull String wrappingPublicKey) {
        if (proofPublicKey.equals(wrappingPublicKey)) {
            return true;
        }
        try {
            return Arrays.equals(
                    Base64.getDecoder().decode(proofPublicKey),
                    Base64.getDecoder().decode(wrappingPublicKey));
        } catch (IllegalArgumentException ignored) {
            return false;
        }
    }
}
