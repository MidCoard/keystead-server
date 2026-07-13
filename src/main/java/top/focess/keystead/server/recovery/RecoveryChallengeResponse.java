package top.focess.keystead.server.recovery;

import java.time.Instant;
import org.jspecify.annotations.NonNull;

public record RecoveryChallengeResponse(@NonNull String challengeId, @NonNull Instant expiresAt) {}
