package top.focess.keystead.server.vault;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

record VaultKeyRotation(
        @NonNull String ownerId,
        @NonNull String vaultId,
        @NonNull String vaultKeyId,
        @NonNull Instant rotatedAt) {

    VaultKeyRotation {
        requireNotBlank(ownerId, "ownerId");
        requireNotBlank(vaultId, "vaultId");
        requireNotBlank(vaultKeyId, "vaultKeyId");
        Objects.requireNonNull(rotatedAt, "rotatedAt");
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) throw new IllegalArgumentException(field + " must not be blank");
    }
}
