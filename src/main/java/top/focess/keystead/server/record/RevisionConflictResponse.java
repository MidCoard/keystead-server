package top.focess.keystead.server.record;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

public record RevisionConflictResponse(
        @NonNull String code,
        @NonNull String message,
        @NonNull String vaultId,
        @NonNull String secretId,
        long latestRevision,
        long rejectedRevision,
        long serverRevision,
        long clientRevision,
        boolean serverDeleted,
        @NonNull Instant serverUpdatedAt) {

    public RevisionConflictResponse {
        requireNotBlank(code, "code");
        requireNotBlank(message, "message");
        requireNotBlank(vaultId, "vaultId");
        requireNotBlank(secretId, "secretId");
        Objects.requireNonNull(serverUpdatedAt, "serverUpdatedAt");
        if (latestRevision <= 0 || serverRevision <= 0) {
            throw new IllegalArgumentException("Server revision must be positive");
        }
        if (rejectedRevision <= 0 || clientRevision <= 0) {
            throw new IllegalArgumentException("Client revision must be positive");
        }
        if (serverRevision < clientRevision) {
            throw new IllegalArgumentException(
                    "Server revision must be greater than or equal to client revision");
        }
        if (latestRevision != serverRevision || rejectedRevision != clientRevision) {
            throw new IllegalArgumentException("Conflict revision aliases must match");
        }
    }

    static @NonNull RevisionConflictResponse from(@NonNull RevisionConflictException exception) {
        return new RevisionConflictResponse(
                "REVISION_CONFLICT",
                exception.getMessage(),
                exception.vaultId(),
                exception.secretId(),
                exception.latestRevision(),
                exception.rejectedRevision(),
                exception.latestRevision(),
                exception.rejectedRevision(),
                exception.serverDeleted(),
                exception.serverUpdatedAt());
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
