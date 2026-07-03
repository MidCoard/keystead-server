package top.focess.keystead.server.identity;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;

public record DeviceProofRequest(
        @NotBlank @Size(max = 255) @NonNull String challengeId,
        @NotBlank @Size(max = 8192) @NonNull String signature) {}
