package top.focess.keystead.server.automation;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public record AutomationToken(
        @NonNull String tokenHash,
        @NonNull String ownerId,
        @NonNull String principalId,
        @NonNull String vaultId,
        @NonNull String scopes,
        @NonNull Instant expiresAt,
        @NonNull Instant createdAt,
        @Nullable Instant revokedAt,
        @Nullable Instant lastUsedAt) {

    public AutomationToken {
        requireNotBlank(tokenHash, "tokenHash");
        requireNotBlank(ownerId, "ownerId");
        requireNotBlank(principalId, "principalId");
        requireNotBlank(vaultId, "vaultId");
        requireNotBlank(scopes, "scopes");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(createdAt, "createdAt");
        if (!expiresAt.isAfter(createdAt))
            throw new IllegalArgumentException("expiresAt must be after createdAt");
        if (revokedAt != null && revokedAt.isBefore(createdAt))
            throw new IllegalArgumentException("revokedAt must not be before createdAt");
        if (lastUsedAt != null && lastUsedAt.isBefore(createdAt))
            throw new IllegalArgumentException("lastUsedAt must not be before createdAt");
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) throw new IllegalArgumentException(field + " must not be blank");
    }
}
