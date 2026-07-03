package top.focess.keystead.server.record;

import org.jspecify.annotations.NonNull;

public record RevisionConflictResponse(
        @NonNull String code, @NonNull String message, long latestRevision, long rejectedRevision) {

    static @NonNull RevisionConflictResponse from(@NonNull RevisionConflictException exception) {
        return new RevisionConflictResponse(
                "REVISION_CONFLICT",
                exception.getMessage(),
                exception.latestRevision(),
                exception.rejectedRevision());
    }
}
