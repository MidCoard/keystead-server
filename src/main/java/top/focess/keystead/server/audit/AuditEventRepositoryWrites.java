package top.focess.keystead.server.audit;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

interface AuditEventRepositoryWrites {

    void append(@NonNull StoredAuditEvent event, @Nullable String correlationId);
}
