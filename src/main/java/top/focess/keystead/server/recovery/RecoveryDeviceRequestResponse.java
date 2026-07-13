package top.focess.keystead.server.recovery;

import java.time.Instant;
import org.jspecify.annotations.NonNull;

public record RecoveryDeviceRequestResponse(
        @NonNull String requestId,
        @NonNull String username,
        @NonNull String deviceId,
        @NonNull String fingerprint,
        @NonNull RecoveryRequestState state,
        @NonNull Instant expiresAt,
        @NonNull String canonicalRequest) {

    @Override
    public @NonNull String toString() {
        return "RecoveryDeviceRequestResponse[requestId=%s, username=%s, deviceId=%s, fingerprint=%s, state=%s, expiresAt=%s, canonicalRequest=[REDACTED %d chars]]"
                .formatted(
                        requestId,
                        username,
                        deviceId,
                        fingerprint,
                        state,
                        expiresAt,
                        canonicalRequest.length());
    }
}
