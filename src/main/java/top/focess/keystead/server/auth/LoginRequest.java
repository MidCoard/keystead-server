package top.focess.keystead.server.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public record LoginRequest(
        @NotBlank @Size(max = 255) @NonNull String username,
        @NotBlank @Size(max = 1024) @NonNull String password,
        @Size(max = 255) @Nullable String deviceId) {}
