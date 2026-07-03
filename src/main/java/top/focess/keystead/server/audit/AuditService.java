package top.focess.keystead.server.audit;

import java.time.Clock;
import java.util.UUID;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;

@Service
public class AuditService {

    private static final String OUTCOME_SUCCESS = "SUCCESS";
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

    private static @NonNull String escapeJson(@NonNull String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
