package top.focess.keystead.server.identity;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.server.crypto.ServerCryptoAlgorithmRegistry;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record DeviceResponse(
        @NonNull String deviceId,
        @NonNull String keyAlgorithm,
        @NonNull String publicKey,
        @Nullable String wrappingKeyAlgorithm,
        @Nullable String wrappingPublicKey,
        @NonNull Instant createdAt,
        @Nullable Instant verifiedAt,
        @Nullable Instant lastSeenAt,
        @Nullable Instant revokedAt) {

    public DeviceResponse {
        requireNotBlank(deviceId, "deviceId");
        requireNotBlank(keyAlgorithm, "keyAlgorithm");
        requireNotBlank(publicKey, "publicKey");
        Objects.requireNonNull(createdAt, "createdAt");
        if (!ServerCryptoAlgorithmRegistry.isApprovedDeviceProofAlgorithm(keyAlgorithm)) {
            throw new IllegalArgumentException("Device key algorithm is unsupported");
        }
        if ((wrappingKeyAlgorithm == null) != (wrappingPublicKey == null)) {
            throw new IllegalArgumentException(
                    "Wrapping key algorithm and public key must be supplied together");
        }
        if (wrappingKeyAlgorithm != null) {
            requireNotBlank(wrappingKeyAlgorithm, "wrappingKeyAlgorithm");
            requireNotBlank(wrappingPublicKey, "wrappingPublicKey");
            if (!ServerCryptoAlgorithmRegistry.isApprovedDeviceWrappingPublicKeyAlgorithm(
                    wrappingKeyAlgorithm)) {
                throw new IllegalArgumentException(
                        "Device wrapping public key algorithm is unsupported");
            }
        }
        requireNotBeforeCreated("verifiedAt", createdAt, verifiedAt);
        requireNotBeforeCreated("lastSeenAt", createdAt, lastSeenAt);
        requireNotBeforeCreated("revokedAt", createdAt, revokedAt);
    }

    public DeviceResponse(
            @NonNull String deviceId,
            @NonNull String keyAlgorithm,
            @NonNull String publicKey,
            @NonNull Instant createdAt,
            @Nullable Instant verifiedAt,
            @Nullable Instant lastSeenAt,
            @Nullable Instant revokedAt) {
        this(
                deviceId,
                keyAlgorithm,
                publicKey,
                null,
                null,
                createdAt,
                verifiedAt,
                lastSeenAt,
                revokedAt);
    }

    static @NonNull DeviceResponse from(@NonNull StoredDevice device) {
        return new DeviceResponse(
                device.deviceId(),
                device.keyAlgorithm(),
                device.publicKey(),
                device.wrappingKeyAlgorithm(),
                device.wrappingPublicKey(),
                device.createdAt(),
                device.verifiedAt(),
                device.lastSeenAt(),
                device.revokedAt());
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }

    private static void requireNotBeforeCreated(
            @NonNull String field, @NonNull Instant createdAt, @Nullable Instant value) {
        if (value != null && value.isBefore(createdAt)) {
            throw new IllegalArgumentException(field + " must not be before created time");
        }
    }
}
