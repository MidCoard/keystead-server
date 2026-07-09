package top.focess.keystead.server.identity;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

record StoredUser(
        @NonNull String username,
        @NonNull String passwordHash,
        @NonNull Instant createdAt,
        @NonNull Instant updatedAt,
        long tokenVersion) {

    StoredUser {
        Objects.requireNonNull(username, "username");
        Objects.requireNonNull(passwordHash, "passwordHash");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (passwordHash.isBlank()) {
            throw new IllegalArgumentException("Password hash must not be blank");
        }
        if (updatedAt.isBefore(createdAt)) {
            throw new IllegalArgumentException("User updated time must not be before created time");
        }
        if (tokenVersion < 0) {
            throw new IllegalArgumentException("User token version must not be negative");
        }
    }
}
