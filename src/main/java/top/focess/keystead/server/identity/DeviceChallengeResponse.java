package top.focess.keystead.server.identity;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

public record DeviceChallengeResponse(
        @NonNull String deviceId,
        @NonNull String challengeId,
        @NonNull String nonce,
        @NonNull Instant expiresAt) {

    public DeviceChallengeResponse {
        requireNotBlank(deviceId, "deviceId");
        requireNotBlank(challengeId, "challengeId");
        requireNotBlank(nonce, "nonce");
        Objects.requireNonNull(expiresAt, "expiresAt");
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
