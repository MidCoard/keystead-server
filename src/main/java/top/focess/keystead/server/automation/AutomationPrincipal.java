package top.focess.keystead.server.automation;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public record AutomationPrincipal(
        @NonNull String ownerId,
        @NonNull String principalId,
        @NonNull String publicKeyAlgorithm,
        @NonNull String publicKey,
        @NonNull Instant createdAt,
        @NonNull Instant updatedAt,
        @Nullable Instant revokedAt) {

    public AutomationPrincipal {
        requireNotBlank(ownerId, "ownerId");
        requireNotBlank(principalId, "principalId");
        requireNotBlank(publicKeyAlgorithm, "publicKeyAlgorithm");
        requireNotBlank(publicKey, "publicKey");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (updatedAt.isBefore(createdAt))
            throw new IllegalArgumentException("updatedAt must not be before createdAt");
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) throw new IllegalArgumentException(field + " must not be blank");
    }
}
