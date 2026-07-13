package top.focess.keystead.server.identity;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.server.crypto.ServerCryptoAlgorithmRegistry;

record StoredDevice(
        @NonNull String ownerId,
        @NonNull String deviceId,
        @NonNull String keyAlgorithm,
        @NonNull String publicKey,
        @Nullable String wrappingKeyAlgorithm,
        @Nullable String wrappingPublicKey,
        @NonNull Instant createdAt,
        @Nullable Instant verifiedAt,
        @Nullable Instant lastSeenAt,
        @Nullable Instant revokedAt) {

    StoredDevice {
        requireNotBlank(ownerId, "ownerId");
        requireNotBlank(deviceId, "deviceId");
        Objects.requireNonNull(keyAlgorithm, "keyAlgorithm");
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(createdAt, "createdAt");
        if (keyAlgorithm.isBlank()) {
            throw new IllegalArgumentException("Key algorithm must not be blank");
        }
        if (publicKey.isBlank()) {
            throw new IllegalArgumentException("Public key must not be blank");
        }
        if (!ServerCryptoAlgorithmRegistry.isApprovedDeviceProofAlgorithm(keyAlgorithm)) {
            throw new IllegalArgumentException("Device key algorithm is unsupported");
        }
        if ((wrappingKeyAlgorithm == null) != (wrappingPublicKey == null)) {
            throw new IllegalArgumentException(
                    "Wrapping key algorithm and public key must be supplied together");
        }
        if (wrappingKeyAlgorithm != null) {
            if (wrappingKeyAlgorithm.isBlank()) {
                throw new IllegalArgumentException("Wrapping key algorithm must not be blank");
            }
            if (wrappingPublicKey.isBlank()) {
                throw new IllegalArgumentException("Wrapping public key must not be blank");
            }
            if (!ServerCryptoAlgorithmRegistry.isApprovedDeviceWrappingPublicKeyAlgorithm(
                    wrappingKeyAlgorithm)) {
                throw new IllegalArgumentException(
                        "Device wrapping public key algorithm is unsupported");
            }
            if (DeviceKeyMaterial.cannotProveSeparation(
                    keyAlgorithm, publicKey, wrappingKeyAlgorithm, wrappingPublicKey)) {
                throw new IllegalArgumentException(
                        "Device proof and wrapping public keys must be distinct");
            }
        }
        requireNotBeforeCreated("verifiedAt", createdAt, verifiedAt);
        requireNotBeforeCreated("lastSeenAt", createdAt, lastSeenAt);
        requireNotBeforeCreated("revokedAt", createdAt, revokedAt);
    }

    StoredDevice(
            @NonNull String ownerId,
            @NonNull String deviceId,
            @NonNull String keyAlgorithm,
            @NonNull String publicKey,
            @NonNull Instant createdAt,
            @Nullable Instant verifiedAt,
            @Nullable Instant lastSeenAt,
            @Nullable Instant revokedAt) {
        this(
                ownerId,
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
