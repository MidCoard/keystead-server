package top.focess.keystead.server.vault;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

record StoredVault(
        @NonNull String ownerId,
        @NonNull String fingerprint,
        @NonNull String encryptedMetadata,
        @NonNull Instant createdAt,
        @NonNull Instant updatedAt) {

    StoredVault {
        requireNotBlank(ownerId, "ownerId");
        requireNotBlank(fingerprint, "fingerprint");
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

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
