package top.focess.keystead.server.identity;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;

public record DeviceRegistrationRequest(
        @NotBlank @Size(max = 255) @NonNull String deviceId,
        @NotBlank @Size(max = 64) @NonNull String keyAlgorithm,
        @NotBlank @Size(max = IdentityLimits.DEVICE_PUBLIC_KEY_MAX_LENGTH)
                @NonNull String publicKey) {}
