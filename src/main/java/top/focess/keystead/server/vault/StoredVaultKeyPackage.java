package top.focess.keystead.server.vault;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

record StoredVaultKeyPackage(
        @NonNull String ownerId,
        @NonNull String vaultId,
        @NonNull String deviceId,
        @NonNull String keyAlgorithm,
        @NonNull String encryptedVaultKey,
        @NonNull Instant createdAt,
        @NonNull Instant updatedAt) {

    StoredVaultKeyPackage {
        Objects.requireNonNull(ownerId, "ownerId");
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(deviceId, "deviceId");
        Objects.requireNonNull(keyAlgorithm, "keyAlgorithm");
        Objects.requireNonNull(encryptedVaultKey, "encryptedVaultKey");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (keyAlgorithm.isBlank()) {
            throw new IllegalArgumentException("Key algorithm must not be blank");
        }
        if (encryptedVaultKey.isBlank()) {
            throw new IllegalArgumentException("Encrypted vault key must not be blank");
        }
        if (updatedAt.isBefore(createdAt)) {
            throw new IllegalArgumentException(
                    "Vault key package updated time must not be before created time");
        }
    }
}
