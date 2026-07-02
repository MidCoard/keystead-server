package top.focess.keystead.server.identity;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;

public record UserRegistrationRequest(
        @NotBlank @Size(max = 255) @NonNull String username,
        @NotBlank @Size(min = 12, max = 1024) @NonNull String password) {}
