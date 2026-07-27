package top.focess.keystead.server.share;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

public record Share(
        @NonNull String code,
        @NonNull String ownerId,
        @NonNull String payload,
        boolean burnAfterReading,
        @NonNull Instant expiresAt,
        @NonNull Instant createdAt) {

    public Share {
        requireNotBlank(code, "code");
        requireNotBlank(ownerId, "ownerId");
        requireNotBlank(payload, "payload");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(createdAt, "createdAt");
        if (!expiresAt.isAfter(createdAt)) {
            throw new IllegalArgumentException("expiresAt must be after createdAt");
        }
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
