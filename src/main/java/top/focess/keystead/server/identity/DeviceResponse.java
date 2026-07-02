package top.focess.keystead.server.identity;

import java.time.Instant;
import org.jspecify.annotations.NonNull;

public record DeviceResponse(
        @NonNull String deviceId,
        @NonNull String keyAlgorithm,
        @NonNull String publicKey,
        @NonNull Instant createdAt) {

    static @NonNull DeviceResponse from(@NonNull StoredDevice device) {
        return new DeviceResponse(
                device.deviceId(), device.keyAlgorithm(), device.publicKey(), device.createdAt());
    }
}
