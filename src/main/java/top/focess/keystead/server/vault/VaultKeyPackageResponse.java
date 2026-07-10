package top.focess.keystead.server.vault;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.server.crypto.ServerCryptoAlgorithmRegistry;

public record VaultKeyPackageResponse(
        @NonNull String vaultId,
        @NonNull String recipientId,
        @NonNull String deviceId,
        @NonNull String vaultKeyId,
        @NonNull String keyAlgorithm,
        @NonNull String encryptedVaultKey,
        @NonNull Instant createdAt,
        @NonNull Instant updatedAt) {

    VaultKeyPackageResponse(
            @NonNull String vaultId,
            @NonNull String deviceId,
            @NonNull String keyAlgorithm,
            @NonNull String encryptedVaultKey,
            @NonNull Instant createdAt,
            @NonNull Instant updatedAt) {
        this(
                vaultId,
                "legacy",
                deviceId,
                "legacy",
                keyAlgorithm,
                encryptedVaultKey,
                createdAt,
                updatedAt);
    }

    public VaultKeyPackageResponse {
        requireNotBlank(vaultId, "vaultId");
        requireNotBlank(recipientId, "recipientId");
        requireNotBlank(deviceId, "deviceId");
        requireNotBlank(vaultKeyId, "vaultKeyId");
        requireNotBlank(keyAlgorithm, "keyAlgorithm");
        requireNotBlank(encryptedVaultKey, "encryptedVaultKey");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (!ServerCryptoAlgorithmRegistry.isApprovedVaultKeyPackageAlgorithm(keyAlgorithm)) {
            throw new IllegalArgumentException("Key package algorithm is unsupported");
        }
        if (updatedAt.isBefore(createdAt)) {
            throw new IllegalArgumentException(
                    "Vault key package updated time must not be before created time");
        }
    }

    static @NonNull VaultKeyPackageResponse from(@NonNull StoredVaultKeyPackage keyPackage) {
        return new VaultKeyPackageResponse(
                keyPackage.vaultId(),
                keyPackage.recipientId(),
                keyPackage.deviceId(),
                keyPackage.vaultKeyId(),
                keyPackage.keyAlgorithm(),
                keyPackage.encryptedVaultKey(),
                keyPackage.createdAt(),
                keyPackage.updatedAt());
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
