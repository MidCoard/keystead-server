package top.focess.keystead.server.recovery;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;

public record RecoveryChallengeRequest(
        @NotBlank @Size(max = 255) @NonNull String username,
        @NotBlank @Size(max = 128) @NonNull String enrollmentId,
        @Positive long generation) {}
