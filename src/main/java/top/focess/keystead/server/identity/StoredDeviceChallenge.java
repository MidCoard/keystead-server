package top.focess.keystead.server.identity;

import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

record StoredDeviceChallenge(
        @NonNull String ownerId,
        @NonNull String deviceId,
        @NonNull String challengeId,
        @NonNull String nonce,
        @NonNull Instant expiresAt,
        @Nullable Instant usedAt,
        @NonNull Instant createdAt) {}
