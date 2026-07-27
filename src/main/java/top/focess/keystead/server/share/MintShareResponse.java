package top.focess.keystead.server.share;

import java.time.Instant;
import org.jspecify.annotations.NonNull;

public record MintShareResponse(@NonNull String code, @NonNull Instant expiresAt) {}
