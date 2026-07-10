package top.focess.keystead.server.vault;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.server.crypto.ServerCryptoAlgorithmRegistry;

record StoredVaultKeyPackage(
        @NonNull String ownerId,
        @NonNull String vaultId,
        @NonNull String recipientId,
        @NonNull String deviceId,
        @NonNull String vaultKeyId,
        @NonNull String keyAlgorithm,
        @NonNull String encryptedVaultKey,
        @NonNull Instant createdAt,
        @NonNull Instant updatedAt) {

    StoredVaultKeyPackage(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull String deviceId,
            @NonNull String keyAlgorithm,
            @NonNull String encryptedVaultKey,
            @NonNull Instant createdAt,
            @NonNull Instant updatedAt) {
        this(
                ownerId,
                vaultId,
                ownerId,
                deviceId,
                "legacy",
                keyAlgorithm,
                encryptedVaultKey,
                createdAt,
                updatedAt);
    }

    StoredVaultKeyPackage {
        requireNotBlank(ownerId, "ownerId");
        requireNotBlank(vaultId, "vaultId");
        requireNotBlank(recipientId, "recipientId");
        requireNotBlank(deviceId, "deviceId");
        requireNotBlank(vaultKeyId, "vaultKeyId");
        Objects.requireNonNull(keyAlgorithm, "keyAlgorithm");
        Objects.requireNonNull(encryptedVaultKey, "encryptedVaultKey");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (keyAlgorithm.isBlank()) {
            throw new IllegalArgumentException("Key algorithm must not be blank");
        }
        if (!ServerCryptoAlgorithmRegistry.isApprovedVaultKeyPackageAlgorithm(keyAlgorithm)) {
            throw new IllegalArgumentException("Key package algorithm is unsupported");
        }
        if (encryptedVaultKey.isBlank()) {
            throw new IllegalArgumentException("Encrypted vault key must not be blank");
        }
        if (updatedAt.isBefore(createdAt)) {
            throw new IllegalArgumentException(
                    "Vault key package updated time must not be before created time");
        }
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
