package top.focess.keystead.server.vault;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

record StoredVault(
        @NonNull String ownerId,
        @NonNull String vaultId,
        @NonNull String encryptedMetadata,
        @NonNull Instant createdAt,
        @NonNull Instant updatedAt) {

    StoredVault {
        Objects.requireNonNull(ownerId, "ownerId");
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(encryptedMetadata, "encryptedMetadata");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (encryptedMetadata.isBlank()) {
            throw new IllegalArgumentException("Encrypted vault metadata must not be blank");
        }
        if (updatedAt.isBefore(createdAt)) {
            throw new IllegalArgumentException(
                    "Vault updated time must not be before created time");
        }
    }
}
