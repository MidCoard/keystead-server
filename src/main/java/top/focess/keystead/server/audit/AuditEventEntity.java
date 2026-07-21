package top.focess.keystead.server.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

@Entity
@Table(
        name = "audit_events",
        indexes = {
            @Index(name = "idx_audit_events_owner_created", columnList = "owner_id, created_at"),
            @Index(name = "idx_audit_events_owner_vault", columnList = "owner_id, vault_id")
        })
public class AuditEventEntity {

    @Id
    @Column(name = "event_id", nullable = false)
    @NonNull String eventId = "";

    @Column(name = "owner_id", nullable = false)
    @NonNull String ownerId = "";

    @Column(name = "actor_id", nullable = false)
    @NonNull String actorId = "";

    @Column(name = "event_type", nullable = false)
    @NonNull String eventType = "";

    @Column(name = "target_type", nullable = false)
    @NonNull String targetType = "";

    @Column(name = "target_id", nullable = false)
    @NonNull String targetId = "";

    @Column(name = "vault_id")
    @Nullable String vaultId;

    @Column(name = "revision")
    @Nullable Long revision;

    @Column(name = "outcome", nullable = false)
    @NonNull String outcome = "";

    @Column(name = "details", nullable = false, columnDefinition = "text")
    @NonNull String details = "";

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;

    @Column(name = "correlation_id")
    @Nullable String correlationId;

    protected AuditEventEntity() {}

    private AuditEventEntity(@NonNull StoredAuditEvent event, @Nullable String correlationId) {
        this.eventId = event.eventId();
        this.ownerId = event.ownerId();
        this.actorId = event.actorId();
        this.eventType = event.eventType();
        this.targetType = event.targetType();
        this.targetId = event.targetId();
        this.vaultId = event.vaultId();
        this.revision = event.revision();
        this.outcome = event.outcome();
        this.details = event.details();
        this.createdAt = event.createdAt();
        this.correlationId = correlationId;
    }

    static @NonNull AuditEventEntity from(
            @NonNull StoredAuditEvent event, @Nullable String correlationId) {
        return new AuditEventEntity(event, correlationId);
    }

    @NonNull StoredAuditEvent toStored() {
        return new StoredAuditEvent(
                eventId,
                ownerId,
                actorId,
                eventType,
                targetType,
                targetId,
                vaultId,
                revision,
                outcome,
                details,
                createdAt);
    }
}
