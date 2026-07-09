package top.focess.keystead.server.record;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

record StoredEncryptedRecord(
        @NonNull String ownerId,
        @NonNull String vaultId,
        @NonNull String secretId,
        long revision,
        @NonNull String secretType,
        @NonNull String metadata,
        @NonNull String encryptedProfile,
        @NonNull String envelope,
        boolean deleted,
        @NonNull Instant updatedAt) {

    StoredEncryptedRecord {
        Objects.requireNonNull(ownerId, "ownerId");
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(secretId, "secretId");
        Objects.requireNonNull(secretType, "secretType");
        Objects.requireNonNull(metadata, "metadata");
        Objects.requireNonNull(encryptedProfile, "encryptedProfile");
        Objects.requireNonNull(envelope, "envelope");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (revision <= 0) {
            throw new IllegalArgumentException("Record revision must be positive");
        }
        if (deleted) {
            if (!metadata.isBlank() || !encryptedProfile.isBlank() || !envelope.isBlank()) {
                throw new IllegalArgumentException("Tombstone rows must not carry encrypted data");
            }
        } else if (encryptedProfile.isBlank() || envelope.isBlank()) {
            throw new IllegalArgumentException("Active rows must carry encrypted data");
        }
    }
}
