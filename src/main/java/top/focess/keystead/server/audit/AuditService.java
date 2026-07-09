package top.focess.keystead.server.audit;

import java.time.Clock;
import java.util.UUID;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuditService {

    private static final String OUTCOME_SUCCESS = "SUCCESS";
    private static final String OUTCOME_FAILURE = "FAILURE";
    private static final String OUTCOME_CONFLICT = "CONFLICT";
    private static final String TARGET_AUTH = "auth";
    private static final String TARGET_DEVICE = "device";
    private static final String TARGET_KEY_PACKAGE = "key_package";
    private static final String TARGET_RECORD = "record";

    private final AuditEventRepository auditEvents;
    private final Clock clock;

    public AuditService(@NonNull AuditEventRepository auditEvents, @NonNull Clock clock) {
        this.auditEvents = auditEvents;
        this.clock = clock;
    }

    public void recordStored(
            @NonNull String ownerId,
            @NonNull String actorId,
            @NonNull String vaultId,
            @NonNull String secretId,
            long revision,
            @NonNull String secretType,
            boolean deleted) {
        append(
                ownerId,
                actorId,
                AuditEventType.RECORD_STORED,
                vaultId,
                secretId,
                revision,
                safeRecordDetails(secretType, deleted));
    }

    public void recordDeleted(
            @NonNull String ownerId,
            @NonNull String actorId,
            @NonNull String vaultId,
            @NonNull String secretId,
            long revision) {
        append(
                ownerId,
                actorId,
                AuditEventType.RECORD_DELETED,
                vaultId,
                secretId,
                revision,
                "{\"deleted\":true}");
    }

    public void keyPackageStored(
            @NonNull String ownerId,
            @NonNull String actorId,
            @NonNull String vaultId,
            @NonNull String deviceId,
            @NonNull String keyAlgorithm) {
        auditEvents.append(
                new StoredAuditEvent(
                        UUID.randomUUID().toString(),
                        ownerId,
                        actorId,
                        AuditEventType.KEY_PACKAGE_STORED.name(),
                        TARGET_KEY_PACKAGE,
                        deviceId,
                        vaultId,
                        null,
                        OUTCOME_SUCCESS,
                        safeKeyPackageDetails(keyAlgorithm),
                        clock.instant()));
    }

    public void deviceRevoked(
            @NonNull String ownerId, @NonNull String actorId, @NonNull String deviceId) {
        auditEvents.append(
                new StoredAuditEvent(
                        UUID.randomUUID().toString(),
                        ownerId,
                        actorId,
                        AuditEventType.DEVICE_REVOKED.name(),
                        TARGET_DEVICE,
                        deviceId,
                        null,
                        null,
                        OUTCOME_SUCCESS,
                        "{\"revoked\":true}",
                        clock.instant()));
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordRevisionConflict(
            @NonNull String ownerId,
            @NonNull String actorId,
            @NonNull String vaultId,
            @NonNull String secretId,
            long latestRevision,
            long rejectedRevision) {
        auditEvents.append(
                new StoredAuditEvent(
                        UUID.randomUUID().toString(),
                        ownerId,
                        actorId,
                        AuditEventType.RECORD_REVISION_CONFLICT.name(),
                        TARGET_RECORD,
                        secretId,
                        vaultId,
                        rejectedRevision,
                        OUTCOME_CONFLICT,
                        safeConflictDetails(latestRevision, rejectedRevision),
                        clock.instant()));
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void loginFailed(@NonNull String username) {
        auditEvents.append(
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

    private void append(
            @NonNull String ownerId,
            @NonNull String actorId,
            @NonNull AuditEventType eventType,
            @NonNull String vaultId,
            @NonNull String targetId,
            long revision,
            @NonNull String details) {
        auditEvents.append(
                new StoredAuditEvent(
                        UUID.randomUUID().toString(),
                        ownerId,
                        actorId,
                        eventType.name(),
                        TARGET_RECORD,
                        targetId,
                        vaultId,
                        revision,
                        OUTCOME_SUCCESS,
                        details,
                        clock.instant()));
    }

    private static @NonNull String safeRecordDetails(@NonNull String secretType, boolean deleted) {
        return "{\"secretType\":\"" + escapeJson(secretType) + "\",\"deleted\":" + deleted + "}";
    }

    private static @NonNull String safeKeyPackageDetails(@NonNull String keyAlgorithm) {
        return "{\"keyAlgorithm\":\"" + escapeJson(keyAlgorithm) + "\"}";
    }

    private static @NonNull String safeConflictDetails(long latestRevision, long rejectedRevision) {
        return "{\"latestRevision\":"
                + latestRevision
                + ",\"rejectedRevision\":"
                + rejectedRevision
                + "}";
    }

    private static @NonNull String escapeJson(@NonNull String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
