package top.focess.keystead.server.record;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;
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

    private static final Set<String> ALLOWED_SECRET_TYPES =
            Set.of(
                    "LOGIN_PASSWORD",
                    "SECURE_NOTE",
                    "SSH_KEY",
                    "API_TOKEN",
                    "GPG_KEY",
                    "MFA_SECRET",
                    "CERTIFICATE",
                    "GENERIC_SECRET");

    StoredEncryptedRecord {
        requireNotBlank(ownerId, "ownerId");
        requireNotBlank(vaultId, "vaultId");
        requireNotBlank(secretId, "secretId");
        Objects.requireNonNull(secretType, "secretType");
        Objects.requireNonNull(metadata, "metadata");
        Objects.requireNonNull(encryptedProfile, "encryptedProfile");
        Objects.requireNonNull(envelope, "envelope");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (revision <= 0) {
            throw new IllegalArgumentException("Record revision must be positive");
        }
        if (!ALLOWED_SECRET_TYPES.contains(secretType)) {
            throw new IllegalArgumentException("Record secret type is unsupported");
        }
        if (deleted) {
            if (!metadata.isBlank() || !encryptedProfile.isBlank() || !envelope.isBlank()) {
                throw new IllegalArgumentException("Tombstone rows must not carry encrypted data");
            }
        } else if (encryptedProfile.isBlank() || envelope.isBlank()) {
            throw new IllegalArgumentException("Active rows must carry encrypted data");
        }
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
