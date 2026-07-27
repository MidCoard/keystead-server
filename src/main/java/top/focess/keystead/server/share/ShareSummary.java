package top.focess.keystead.server.share;

import java.time.Instant;
import org.jspecify.annotations.NonNull;

public record ShareSummary(
        @NonNull String code,
        @NonNull Instant createdAt,
        @NonNull Instant expiresAt,
        boolean burnAfterReading) {}
