package top.focess.keystead.server.audit;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuditService {

    private static final String OUTCOME_SUCCESS = "SUCCESS";
    private static final String OUTCOME_FAILURE = "FAILURE";
    private static final String TARGET_AUTH = "auth";
    private static final String TARGET_RECORD = "record";

    private final AuditEventRepository auditEvents;
    private final Clock clock;
    private final CorrelationIdHolder correlationIds;
    private final AuditProperties auditProperties;
    private final AuditSigner signer;

    public AuditService(
            @NonNull AuditEventRepository auditEvents,
            @NonNull Clock clock,
            @NonNull CorrelationIdHolder correlationIds,
            @NonNull AuditProperties auditProperties,
            @NonNull AuditSigner signer) {
        this.auditEvents = auditEvents;
        this.clock = clock;
        this.correlationIds = correlationIds;
        this.auditProperties = auditProperties;
        this.signer = signer;
    }

    @Transactional(readOnly = true)
    public @NonNull AuditEventPageResponse pageForOwner(
            @NonNull String ownerId,
            int limit,
            @Nullable String fingerprint,
            @Nullable Instant before,
            @Nullable String beforeId) {
        if (limit <= 0 || limit > auditProperties.queryMaxLimit()) {
            throw new InvalidAuditRequestException("Audit page limit is out of range");
        }
        if ((before == null) != (beforeId == null)) {
            throw new InvalidAuditRequestException(
                    "Audit cursor must specify both before and beforeId");
        }
        List<AuditEventEntity> fetched =
                before == null
                        ? auditEvents.pageFirst(ownerId, fingerprint, limit + 1)
                        : auditEvents.pageCursor(ownerId, fingerprint, before, beforeId, limit + 1);
        boolean hasMore = fetched.size() > limit;
        List<AuditEventResponse> page =
                fetched.stream().limit(limit).map(AuditEventResponse::from).toList();
        Instant nextBefore = null;
        String nextBeforeId = null;
        if (hasMore && !page.isEmpty()) {
            AuditEventResponse oldest = page.get(page.size() - 1);
            nextBefore = oldest.createdAt();
            nextBeforeId = oldest.eventId();
        }
        return new AuditEventPageResponse(page, limit, hasMore, nextBefore, nextBeforeId);
    }

    public void recordStored(
            @NonNull String ownerId,
            @NonNull String fingerprint,
            @NonNull String secretId,
            long revision,
            @NonNull String secretType) {
        appendRecord(
                ownerId,
                AuditEventType.RECORD_STORED,
                fingerprint,
                secretId,
                revision,
                "{\"secretType\":\"" + escapeJson(secretType) + "\",\"deleted\":false}");
    }

    public void recordDeleted(
            @NonNull String ownerId,
            @NonNull String fingerprint,
            @NonNull String secretId,
            long revision) {
        appendRecord(
                ownerId,
                AuditEventType.RECORD_DELETED,
                fingerprint,
                secretId,
                revision,
                "{\"deleted\":true}");
    }

    public void recordPurged(
            @NonNull String ownerId,
            @NonNull String fingerprint,
            @NonNull String secretId,
            long deletedEvents) {
        persist(
                new StoredAuditEvent(
                        UUID.randomUUID().toString(),
                        ownerId,
                        ownerId,
                        AuditEventType.RECORD_PURGED.name(),
                        TARGET_RECORD,
                        secretId,
                        fingerprint,
                        null,
                        OUTCOME_SUCCESS,
                        "{\"deletedEvents\":" + deletedEvents + "}",
                        clock.instant()));
    }

    @Transactional
    public void loginFailed(@NonNull String username) {
        persist(
                new StoredAuditEvent(
                        UUID.randomUUID().toString(),
                        username,
                        username,
                        AuditEventType.LOGIN_FAILED.name(),
                        TARGET_AUTH,
                        username,
                        null,
                        null,
                        OUTCOME_FAILURE,
                        "{\"reason\":\"BAD_CREDENTIALS\"}",
                        clock.instant()));
    }

    private void appendRecord(
            @NonNull String ownerId,
            @NonNull AuditEventType eventType,
            @NonNull String fingerprint,
            @NonNull String secretId,
            long revision,
            @NonNull String details) {
        persist(
                new StoredAuditEvent(
                        UUID.randomUUID().toString(),
                        ownerId,
                        ownerId,
                        eventType.name(),
                        TARGET_RECORD,
                        secretId,
                        fingerprint,
                        revision,
                        OUTCOME_SUCCESS,
                        details,
                        clock.instant()));
    }

    private void persist(@NonNull StoredAuditEvent event) {
        StoredAuditEvent stored = withStoragePrecision(event);
        auditEvents.append(stored, correlationIds.current(), signer.sign(stored));
        Duration retention = auditProperties.retention();
        if (retention != null) {
            auditEvents.deleteOlderThan(stored.ownerId(), clock.instant().minus(retention));
        }
    }

    private static @NonNull StoredAuditEvent withStoragePrecision(@NonNull StoredAuditEvent event) {
        Instant createdAt = event.createdAt().truncatedTo(ChronoUnit.MILLIS);
        if (createdAt.equals(event.createdAt())) {
            return event;
        }
        return new StoredAuditEvent(
                event.eventId(),
                event.ownerId(),
                event.actorId(),
                event.eventType(),
                event.targetType(),
                event.targetId(),
                event.fingerprint(),
                event.revision(),
                event.outcome(),
                event.details(),
                createdAt);
    }

    private static @NonNull String escapeJson(@NonNull String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
