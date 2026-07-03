package top.focess.keystead.server.identity;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record DeviceResponse(
        @NonNull String deviceId,
        @NonNull String keyAlgorithm,
        @NonNull String publicKey,
        @NonNull Instant createdAt,
        @Nullable Instant verifiedAt,
        @Nullable Instant lastSeenAt,
        @Nullable Instant revokedAt) {

    static @NonNull DeviceResponse from(@NonNull StoredDevice device) {
        return new DeviceResponse(
                device.deviceId(),
                device.keyAlgorithm(),
                device.publicKey(),
                device.createdAt(),
                device.verifiedAt(),
                device.lastSeenAt(),
                device.revokedAt());
    }
}
