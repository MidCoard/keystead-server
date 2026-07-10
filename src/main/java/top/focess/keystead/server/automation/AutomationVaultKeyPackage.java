package top.focess.keystead.server.automation;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

record AutomationVaultKeyPackage(
        @NonNull String ownerId,
        @NonNull String vaultId,
        @NonNull String principalId,
        @NonNull String vaultKeyId,
        @NonNull String keyAlgorithm,
        @NonNull String encryptedVaultKey,
        @NonNull Instant createdAt,
        @NonNull Instant updatedAt) {

    AutomationVaultKeyPackage {
        requireNotBlank(ownerId, "ownerId");
        requireNotBlank(vaultId, "vaultId");
        requireNotBlank(principalId, "principalId");
        requireNotBlank(vaultKeyId, "vaultKeyId");
        requireNotBlank(keyAlgorithm, "keyAlgorithm");
        requireNotBlank(encryptedVaultKey, "encryptedVaultKey");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (updatedAt.isBefore(createdAt)) {
            throw new IllegalArgumentException("updatedAt must not be before createdAt");
        }
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
