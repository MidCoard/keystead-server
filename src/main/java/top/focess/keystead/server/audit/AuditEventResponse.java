package top.focess.keystead.server.audit;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Read view of one audit event. Unlike {@link StoredAuditEvent} this view also exposes the {@code
 * correlationId} captured at append time, so callers correlating a request across services can page
 * through their own trail without a separate lookup.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuditEventResponse(
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
        @NonNull Instant createdAt,
        @Nullable String correlationId,
        @Nullable String signature) {

    public AuditEventResponse {
        requireNotBlank(eventId, "eventId");
        requireNotBlank(ownerId, "ownerId");
        requireNotBlank(actorId, "actorId");
        requireNotBlank(eventType, "eventType");
        requireNotBlank(targetType, "targetType");
        requireNotBlank(targetId, "targetId");
        requireNotBlank(outcome, "outcome");
        Objects.requireNonNull(details, "details");
        Objects.requireNonNull(createdAt, "createdAt");
    }

    static @NonNull AuditEventResponse from(@NonNull AuditEventEntity entity) {
        return new AuditEventResponse(
                entity.eventId,
                entity.ownerId,
                entity.actorId,
                entity.eventType,
                entity.targetType,
                entity.targetId,
                entity.vaultId,
                entity.revision,
                entity.outcome,
                entity.details,
                entity.createdAt,
                entity.correlationId,
                entity.signature);
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
