package top.focess.keystead.server.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;

public record RefreshTokenRequest(@NotBlank @Size(max = 4096) @NonNull String refreshToken) {}
