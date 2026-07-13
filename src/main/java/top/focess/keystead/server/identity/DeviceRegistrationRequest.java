package top.focess.keystead.server.identity;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.server.crypto.ServerCryptoAlgorithmRegistry;

public record DeviceRegistrationRequest(
        @NotBlank @Size(max = 255) @NonNull String deviceId,
        @NotBlank @Size(max = 64) @NonNull String keyAlgorithm,
        @NotBlank @Size(max = IdentityLimits.DEVICE_PUBLIC_KEY_MAX_LENGTH)
                @NonNull String publicKey,
        @Size(max = 64) @Nullable String wrappingKeyAlgorithm,
        @Size(max = IdentityLimits.DEVICE_PUBLIC_KEY_MAX_LENGTH)
                @Nullable String wrappingPublicKey) {

    public DeviceRegistrationRequest(
            @NonNull String deviceId, @NonNull String keyAlgorithm, @NonNull String publicKey) {
        this(deviceId, keyAlgorithm, publicKey, null, null);
    }

    void validateShape() {
        if ((wrappingKeyAlgorithm == null) != (wrappingPublicKey == null)) {
            throw new InvalidDeviceRegistrationRequestException(
                    "Wrapping key algorithm and public key must be supplied together");
        }
        if (wrappingKeyAlgorithm == null) {
            return;
        }
        if (wrappingKeyAlgorithm.isBlank() || wrappingPublicKey.isBlank()) {
            throw new InvalidDeviceRegistrationRequestException(
                    "Wrapping key algorithm and public key are required");
        }
        if (!ServerCryptoAlgorithmRegistry.isApprovedDeviceWrappingPublicKeyAlgorithm(
                wrappingKeyAlgorithm)) {
            throw new InvalidDeviceRegistrationRequestException(
                    "Unsupported device wrapping public key algorithm");
        }
        if (DeviceKeyMaterial.cannotProveSeparation(
                keyAlgorithm, publicKey, wrappingKeyAlgorithm, wrappingPublicKey)) {
            throw new InvalidDeviceRegistrationRequestException(
                    "Device proof and wrapping public keys must be distinct");
        }
    }
}
