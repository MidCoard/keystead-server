package top.focess.keystead.server.identity;

import java.time.Instant;
import org.jspecify.annotations.NonNull;

record StoredDevice(
        @NonNull String ownerId,
        @NonNull String deviceId,
        @NonNull String keyAlgorithm,
        @NonNull String publicKey,
        @NonNull Instant createdAt) {}
