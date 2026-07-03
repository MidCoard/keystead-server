package top.focess.keystead.server.record;

import java.time.Instant;
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
}
