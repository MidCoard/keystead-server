package top.focess.keystead.server.identity;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;

public record UserRegistrationRequest(
        @NotBlank @Size(max = 255) @NonNull String username,
        // Minimum length is a security policy; the previous upper bound of 72
        // was a bcrypt artifact. The PreHashedPasswordEncoder wraps bcrypt and
        // pre-hashes the raw credential with SHA-256, so any-length passphrase
        // is accepted at this layer.
        @NotBlank @Size(min = 12) @NonNull String password) {}
