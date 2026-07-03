package top.focess.keystead.server.record;

import java.time.Instant;
import org.jspecify.annotations.NonNull;

final class RevisionConflictException extends RuntimeException {

    private final String vaultId;
    private final String secretId;
    private final long latestRevision;
    private final long rejectedRevision;
    private final boolean serverDeleted;
    private final Instant serverUpdatedAt;

    RevisionConflictException(
            @NonNull String message,
            @NonNull String vaultId,
            @NonNull String secretId,
            long latestRevision,
            long rejectedRevision,
            boolean serverDeleted,
            @NonNull Instant serverUpdatedAt) {
        super(message);
        this.vaultId = vaultId;
        this.secretId = secretId;
        this.latestRevision = latestRevision;
        this.rejectedRevision = rejectedRevision;
        this.serverDeleted = serverDeleted;
        this.serverUpdatedAt = serverUpdatedAt;
    }

    @NonNull String vaultId() {
        return vaultId;
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
}
