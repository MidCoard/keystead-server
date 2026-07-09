package top.focess.keystead.server.auth;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

record StoredRefreshToken(
        @NonNull String tokenHash,
        @NonNull String username,
        @Nullable String deviceId,
        @NonNull Instant refreshExpiresAt,
        @Nullable Instant revokedAt,
        @NonNull Instant createdAt,
        @NonNull Instant lastUsedAt) {

    StoredRefreshToken {
        Objects.requireNonNull(tokenHash, "tokenHash");
        Objects.requireNonNull(username, "username");
        Objects.requireNonNull(refreshExpiresAt, "refreshExpiresAt");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(lastUsedAt, "lastUsedAt");
        if (tokenHash.isBlank()) {
            throw new IllegalArgumentException("Refresh token hash must not be blank");
        }
        if (username.isBlank()) {
            throw new IllegalArgumentException("Refresh token username must not be blank");
        }
        if (!refreshExpiresAt.isAfter(createdAt)) {
            throw new IllegalArgumentException("Refresh token expiry must be after creation");
        }
        requireNotBeforeCreated("revokedAt", createdAt, revokedAt);
        requireNotBeforeCreated("lastUsedAt", createdAt, lastUsedAt);
    }

    @NonNull StoredRefreshToken withLastUsedAt(@NonNull Instant value) {
        return new StoredRefreshToken(
                tokenHash, username, deviceId, refreshExpiresAt, revokedAt, createdAt, value);
    }

    @NonNull StoredRefreshToken revoked(@NonNull Instant value) {
        return new StoredRefreshToken(
                tokenHash, username, deviceId, refreshExpiresAt, value, createdAt, lastUsedAt);
    }

    private static void requireNotBeforeCreated(
            @NonNull String field, @NonNull Instant createdAt, @Nullable Instant value) {
        if (value != null && value.isBefore(createdAt)) {
            throw new IllegalArgumentException(field + " must not be before created time");
        }
    }
}
