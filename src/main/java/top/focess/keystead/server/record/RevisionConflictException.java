package top.focess.keystead.server.record;

import org.jspecify.annotations.NonNull;

final class RevisionConflictException extends RuntimeException {

    private final long latestRevision;
    private final long rejectedRevision;

    RevisionConflictException(@NonNull String message, long latestRevision, long rejectedRevision) {
        super(message);
        this.latestRevision = latestRevision;
        this.rejectedRevision = rejectedRevision;
    }

    long latestRevision() {
        return latestRevision;
    }

    long rejectedRevision() {
        return rejectedRevision;
    }
}
