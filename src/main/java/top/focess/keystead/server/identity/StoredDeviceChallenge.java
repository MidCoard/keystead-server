package top.focess.keystead.server.identity;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

record StoredDeviceChallenge(
        @NonNull String ownerId,
        @NonNull String deviceId,
        @NonNull String challengeId,
        @NonNull String nonce,
        @NonNull Instant expiresAt,
        @Nullable Instant usedAt,
        @NonNull Instant createdAt) {

    StoredDeviceChallenge {
        requireNotBlank(ownerId, "ownerId");
        requireNotBlank(deviceId, "deviceId");
        requireNotBlank(challengeId, "challengeId");
        Objects.requireNonNull(nonce, "nonce");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(createdAt, "createdAt");
        if (nonce.isBlank()) {
            throw new IllegalArgumentException("Challenge nonce must not be blank");
        }
        if (expiresAt.isBefore(createdAt)) {
            throw new IllegalArgumentException("Challenge expiry must not be before created time");
        }
        if (usedAt != null && (usedAt.isBefore(createdAt) || usedAt.isAfter(expiresAt))) {
            throw new IllegalArgumentException(
                    "Challenge used time must be inside challenge window");
        }
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
