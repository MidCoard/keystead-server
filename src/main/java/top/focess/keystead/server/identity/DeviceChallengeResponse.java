package top.focess.keystead.server.identity;

import java.time.Instant;
import org.jspecify.annotations.NonNull;

public record DeviceChallengeResponse(
        @NonNull String deviceId,
        @NonNull String challengeId,
        @NonNull String nonce,
        @NonNull Instant expiresAt) {}
