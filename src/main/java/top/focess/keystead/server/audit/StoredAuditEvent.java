package top.focess.keystead.server.audit;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;
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
        @NonNull Instant createdAt) {

    private static final Set<String> ALLOWED_OUTCOMES = Set.of("SUCCESS", "FAILURE", "CONFLICT");
    private static final Set<String> ALLOWED_TARGET_TYPES =
            Set.of("auth", "device", "key_package", "record");

    public StoredAuditEvent {
        requireNotBlank(eventId, "eventId");
        requireNotBlank(ownerId, "ownerId");
        requireNotBlank(actorId, "actorId");
        requireNotBlank(eventType, "eventType");
        try {
            AuditEventType.valueOf(eventType);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Audit event type is unsupported", e);
        }
        requireNotBlank(targetType, "targetType");
        if (!ALLOWED_TARGET_TYPES.contains(targetType)) {
            throw new IllegalArgumentException("Audit target type is unsupported");
        }
        requireNotBlank(targetId, "targetId");
        if (vaultId != null && vaultId.isBlank()) {
            throw new IllegalArgumentException("vaultId must not be blank");
        }
        if (revision != null && revision <= 0) {
            throw new IllegalArgumentException("Audit revision must be positive");
        }
        requireNotBlank(outcome, "outcome");
        if (!ALLOWED_OUTCOMES.contains(outcome)) {
            throw new IllegalArgumentException("Audit outcome is unsupported");
        }
        requireNotBlank(details, "details");
        Objects.requireNonNull(createdAt, "createdAt");
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
