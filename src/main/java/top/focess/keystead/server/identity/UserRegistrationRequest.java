package top.focess.keystead.server.identity;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;

public record UserRegistrationRequest(
        @NotBlank @Size(max = 255) @NonNull String username,
        // Preserve support for long credentials; pre-hashing handles bcrypt's 72-byte ceiling.
        @NotBlank @Size(min = 12) @NonNull String password) {}
