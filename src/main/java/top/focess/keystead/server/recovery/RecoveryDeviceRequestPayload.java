package top.focess.keystead.server.recovery;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;

public record RecoveryDeviceRequestPayload(
        @NotBlank @Size(max = 255) @NonNull String username,
        @NotBlank @Size(max = 255) @NonNull String deviceId,
        @NotBlank @Size(max = 64) @NonNull String proofKeyAlgorithm,
        @NotBlank @Size(max = RecoveryLimits.PUBLIC_KEY_MAX_LENGTH) @NonNull String proofPublicKey,
        @NotBlank @Size(max = 64) @NonNull String wrappingKeyAlgorithm,
        @NotBlank @Size(max = RecoveryLimits.PUBLIC_KEY_MAX_LENGTH)
                @NonNull String wrappingPublicKey) {

    @Override
    public @NonNull String toString() {
        return "RecoveryDeviceRequestPayload[username=%s, deviceId=%s, proofKeyAlgorithm=%s, proofPublicKey=[PUBLIC %d chars], wrappingKeyAlgorithm=%s, wrappingPublicKey=[PUBLIC %d chars]]"
                .formatted(
                        username,
                        deviceId,
                        proofKeyAlgorithm,
                        proofPublicKey.length(),
                        wrappingKeyAlgorithm,
                        wrappingPublicKey.length());
    }
}
