package top.focess.keystead.server.share;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public record MintShareRequest(
        @NotBlank @Size(max = ShareService.MAX_PAYLOAD_LENGTH) @NonNull String payload,
        @Nullable Instant expiresAt,
        @Nullable Boolean burnAfterReading) {}
