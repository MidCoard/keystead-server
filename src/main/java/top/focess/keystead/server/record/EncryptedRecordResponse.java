package top.focess.keystead.server.record;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record EncryptedRecordResponse(
        @NonNull String vaultId,
        @NonNull String secretId,
        long revision,
        @NonNull String secretType,
        @Nullable String metadata,
        @Nullable String encryptedProfile,
        @Nullable String envelope,
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

    public EncryptedRecordResponse {
        requireNotBlank(vaultId, "vaultId");
        requireNotBlank(secretId, "secretId");
        Objects.requireNonNull(secretType, "secretType");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (revision <= 0) {
            throw new IllegalArgumentException("Record revision must be positive");
        }
        if (!ALLOWED_SECRET_TYPES.contains(secretType)) {
            throw new IllegalArgumentException("Record secret type is unsupported");
        }
        if (metadata != null) {
            throw new IllegalArgumentException("Record response must not expose metadata alias");
        }
        if (deleted) {
            if (hasText(encryptedProfile) || hasText(envelope)) {
                throw new IllegalArgumentException(
                        "Tombstone responses must not expose encrypted data");
            }
        } else if (!hasText(encryptedProfile) || !hasText(envelope)) {
            throw new IllegalArgumentException("Active responses must expose encrypted data");
        }
    }

    static @NonNull EncryptedRecordResponse from(@NonNull StoredEncryptedRecord record) {
        boolean deleted = record.deleted();
        return new EncryptedRecordResponse(
                record.vaultId(),
                record.secretId(),
                record.revision(),
                record.secretType(),
                null,
                deleted ? null : record.encryptedProfile(),
                deleted ? null : record.envelope(),
                deleted,
                record.updatedAt());
    }

    private static boolean hasText(@Nullable String value) {
        return value != null && !value.isBlank();
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
