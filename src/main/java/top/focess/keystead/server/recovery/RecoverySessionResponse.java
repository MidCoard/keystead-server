package top.focess.keystead.server.recovery;

import java.time.Instant;
import org.jspecify.annotations.NonNull;

public record RecoverySessionResponse(@NonNull String token, @NonNull Instant expiresAt) {

    @Override
    public @NonNull String toString() {
        return "RecoverySessionResponse[token=[REDACTED %d chars], expiresAt=%s]"
                .formatted(token.length(), expiresAt);
    }
}
