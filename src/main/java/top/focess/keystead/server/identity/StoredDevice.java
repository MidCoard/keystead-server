package top.focess.keystead.server.identity;

import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

record StoredDevice(
        @NonNull String ownerId,
        @NonNull String deviceId,
        @NonNull String keyAlgorithm,
        @NonNull String publicKey,
        @NonNull Instant createdAt,
        @Nullable Instant verifiedAt,
        @Nullable Instant lastSeenAt,
        @Nullable Instant revokedAt) {}
