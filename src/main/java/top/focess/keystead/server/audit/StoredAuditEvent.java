package top.focess.keystead.server.audit;

import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public record StoredAuditEvent(
        @NonNull String eventId,
        @NonNull String ownerId,
        @NonNull String actorId,
        @NonNull String eventType,
        @NonNull String targetType,
        @NonNull String targetId,
        @Nullable String vaultId,
        @Nullable Long revision,
        @NonNull String outcome,
        @NonNull String details,
        @NonNull Instant createdAt) {}
