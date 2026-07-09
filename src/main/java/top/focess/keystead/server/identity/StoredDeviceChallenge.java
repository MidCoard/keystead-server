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
        Objects.requireNonNull(ownerId, "ownerId");
        Objects.requireNonNull(deviceId, "deviceId");
        Objects.requireNonNull(challengeId, "challengeId");
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
}
