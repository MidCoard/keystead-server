package top.focess.keystead.server.identity;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;
import top.focess.keystead.server.crypto.ServerCryptoAlgorithmRegistry;

@Component
public class DeviceSignatureVerifier {

    private final DeviceRepository devices;

    DeviceSignatureVerifier(@NonNull DeviceRepository devices) {
        this.devices = devices;
    }

    public boolean verifyVerifiedDevice(
            @NonNull String ownerId,
            @NonNull String deviceId,
            byte @NonNull [] payload,
            @NonNull String encodedSignature) {
        return devices.find(ownerId, deviceId)
                .filter(device -> device.verifiedAt() != null && device.revokedAt() == null)
                .filter(device -> verifyRegisteredDevice(device, payload, encodedSignature))
                .isPresent();
    }

    boolean verifyRegisteredDevice(
            @NonNull StoredDevice device,
            byte @NonNull [] payload,
            @NonNull String encodedSignature) {
        return verifyPublicKey(
                device.keyAlgorithm(), device.publicKey(), payload, encodedSignature);
    }

    public boolean verifyPublicKey(
            @NonNull String keyAlgorithm,
            @NonNull String encodedPublicKey,
            byte @NonNull [] payload,
            @NonNull String encodedSignature) {
        try {
            Signature signature = Signature.getInstance(signatureAlgorithm(keyAlgorithm));
            configureSignature(signature, keyAlgorithm);
            signature.initVerify(publicKey(keyAlgorithm, encodedPublicKey));
            signature.update(payload);
            return signature.verify(Base64.getDecoder().decode(encodedSignature));
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            return false;
        }
    }

    public boolean isValidPublicKey(
            @NonNull String keyAlgorithm, @NonNull String encodedPublicKey) {
        try {
            publicKey(keyAlgorithm, encodedPublicKey);
            return true;
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            return false;
        }
    }

    private @NonNull PublicKey publicKey(
            @NonNull String keyAlgorithm, @NonNull String encodedPublicKey)
            throws GeneralSecurityException {
        byte[] keyBytes = Base64.getDecoder().decode(encodedPublicKey);
        return KeyFactory.getInstance(keyFactoryAlgorithm(keyAlgorithm))
                .generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    private @NonNull String signatureAlgorithm(@NonNull String keyAlgorithm) {
        return switch (keyAlgorithm) {
            case ServerCryptoAlgorithmRegistry.DEVICE_RSA_OAEP_SHA256 -> "SHA256withRSA";
            case ServerCryptoAlgorithmRegistry.DEVICE_RSA_PSS_SHA256 -> "RSASSA-PSS";
            case ServerCryptoAlgorithmRegistry.DEVICE_ECDSA_P256_SHA256 -> "SHA256withECDSA";
            case ServerCryptoAlgorithmRegistry.DEVICE_ECDSA_P384_SHA384 -> "SHA384withECDSA";
            case ServerCryptoAlgorithmRegistry.DEVICE_ECDSA_P521_SHA512 -> "SHA512withECDSA";
            case ServerCryptoAlgorithmRegistry.DEVICE_ED25519 -> "Ed25519";
            default -> throw new IllegalArgumentException("Unsupported device key algorithm");
        };
    }

    private void configureSignature(@NonNull Signature signature, @NonNull String keyAlgorithm)
            throws GeneralSecurityException {
        @Nullable AlgorithmParameterSpec parameters =
                switch (keyAlgorithm) {
                    case ServerCryptoAlgorithmRegistry.DEVICE_RSA_PSS_SHA256 ->
                            rsaPssSha256Parameters();
                    default -> null;
                };
        if (parameters != null) {
            signature.setParameter(parameters);
        }
    }

    private @NonNull PSSParameterSpec rsaPssSha256Parameters() {
        return new PSSParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, PSSParameterSpec.TRAILER_FIELD_BC);
    }

    private @NonNull String keyFactoryAlgorithm(@NonNull String keyAlgorithm) {
        return switch (keyAlgorithm) {
            case ServerCryptoAlgorithmRegistry.DEVICE_RSA_OAEP_SHA256,
                    ServerCryptoAlgorithmRegistry.DEVICE_RSA_PSS_SHA256 ->
                    "RSA";
            case ServerCryptoAlgorithmRegistry.DEVICE_ECDSA_P256_SHA256,
                    ServerCryptoAlgorithmRegistry.DEVICE_ECDSA_P384_SHA384,
                    ServerCryptoAlgorithmRegistry.DEVICE_ECDSA_P521_SHA512 ->
                    "EC";
            case ServerCryptoAlgorithmRegistry.DEVICE_ED25519 -> "Ed25519";
            default -> throw new IllegalArgumentException("Unsupported device key algorithm");
        };
    }
}
