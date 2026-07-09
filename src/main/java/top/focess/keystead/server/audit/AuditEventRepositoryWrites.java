package top.focess.keystead.server.audit;

import org.jspecify.annotations.NonNull;

interface AuditEventRepositoryWrites {

    void append(@NonNull StoredAuditEvent event);
}
