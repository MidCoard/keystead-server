package top.focess.keystead.server.identity;

import java.time.Instant;
import org.jspecify.annotations.NonNull;

record StoredUser(
        @NonNull String username,
        @NonNull String passwordHash,
        @NonNull Instant createdAt,
        @NonNull Instant updatedAt) {}
