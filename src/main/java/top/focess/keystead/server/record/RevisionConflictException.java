package top.focess.keystead.server.record;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

final class RevisionConflictException extends RuntimeException {

    private final String fingerprint;
    private final String secretId;
    private final long latestRevision;
    private final long rejectedRevision;
    private final boolean serverDeleted;
    private final Instant serverUpdatedAt;

    RevisionConflictException(
            @NonNull String message,
            @NonNull String fingerprint,
            @NonNull String secretId,
            long latestRevision,
            long rejectedRevision,
            boolean serverDeleted,
            @NonNull Instant serverUpdatedAt) {
        this(
                message,
                fingerprint,
                secretId,
                latestRevision,
                rejectedRevision,
                serverDeleted,
                serverUpdatedAt,
                null);
    }

    RevisionConflictException(
            @NonNull String message,
            @NonNull String fingerprint,
            @NonNull String secretId,
            long latestRevision,
            long rejectedRevision,
            boolean serverDeleted,
            @NonNull Instant serverUpdatedAt,
            @Nullable Throwable cause) {
        super(requireNotBlank(message, "message"), cause);
        this.fingerprint = requireNotBlank(fingerprint, "fingerprint");
        this.secretId = requireNotBlank(secretId, "secretId");
        if (latestRevision <= 0) {
            throw new IllegalArgumentException("latestRevision must be positive");
        }
        if (rejectedRevision <= 0) {
            throw new IllegalArgumentException("rejectedRevision must be positive");
        }
        if (latestRevision < rejectedRevision) {
            throw new IllegalArgumentException(
                    "latestRevision must be greater than or equal to rejectedRevision");
        }
        this.latestRevision = latestRevision;
        this.rejectedRevision = rejectedRevision;
        this.serverDeleted = serverDeleted;
        this.serverUpdatedAt = Objects.requireNonNull(serverUpdatedAt, "serverUpdatedAt");
    }

    @NonNull String fingerprint() {
        return fingerprint;
    }

    @NonNull String secretId() {
        return secretId;
    }

    long latestRevision() {
        return latestRevision;
    }

    long rejectedRevision() {
        return rejectedRevision;
    }

    boolean serverDeleted() {
        return serverDeleted;
    }

    @NonNull Instant serverUpdatedAt() {
        return serverUpdatedAt;
    }

    private static @NonNull String requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }
}
