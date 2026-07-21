package top.focess.keystead.server.audit;

import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

interface AuditEventRepositoryWrites {

    void append(
            @NonNull StoredAuditEvent event,
            @Nullable String correlationId,
            @Nullable String signature);

    /**
     * Bulk-deletes audit events for one owner older than {@code cutoff}. Routed through the write
     * impl so retention pruning stays inside the same JPA service boundary as appends.
     *
     * @return the number of rows deleted.
     */
    int deleteOlderThan(@NonNull String ownerId, @NonNull Instant cutoff);
}
