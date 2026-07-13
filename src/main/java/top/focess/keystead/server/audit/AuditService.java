package top.focess.keystead.server.audit;

import java.time.Clock;
import java.util.UUID;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
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
    private static final String TARGET_AUTOMATION_PRINCIPAL = "automation_principal";
    private static final String TARGET_AUTOMATION_TOKEN = "automation_token";
    private static final String TARGET_RECORD = "record";
    private static final String TARGET_RECOVERY_ENROLLMENT = "recovery_enrollment";
    private static final String TARGET_RECOVERY_SESSION = "recovery_session";

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
            @NonNull String vaultKeyId,
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
                        safeKeyPackageDetails(vaultKeyId, keyAlgorithm),
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

    public void automationPrincipalStored(
            @NonNull String ownerId,
            @NonNull String principalId,
            @NonNull String vaultId,
            @NonNull String keyAlgorithm) {
        appendAutomation(
                ownerId,
                ownerId,
                AuditEventType.AUTOMATION_PRINCIPAL_STORED,
                TARGET_AUTOMATION_PRINCIPAL,
                principalId,
                vaultId,
                "{\"keyAlgorithm\":\"" + escapeJson(keyAlgorithm) + "\"}");
    }

    public void automationPrincipalRevoked(
            @NonNull String ownerId, @NonNull String principalId, @NonNull String vaultId) {
        appendAutomation(
                ownerId,
                ownerId,
                AuditEventType.AUTOMATION_PRINCIPAL_REVOKED,
                TARGET_AUTOMATION_PRINCIPAL,
                principalId,
                vaultId,
                "{\"revoked\":true}");
    }

    public void automationTokenIssued(
            @NonNull String ownerId,
            @NonNull String principalId,
            @NonNull String vaultId,
            @NonNull String scopes) {
        appendAutomation(
                ownerId,
                ownerId,
                AuditEventType.AUTOMATION_TOKEN_ISSUED,
                TARGET_AUTOMATION_TOKEN,
                principalId,
                vaultId,
                "{\"scopes\":\"" + escapeJson(scopes) + "\"}");
    }

    public void automationTokenRevoked(
            @NonNull String ownerId, @NonNull String principalId, @NonNull String vaultId) {
        appendAutomation(
                ownerId,
                ownerId,
                AuditEventType.AUTOMATION_TOKEN_REVOKED,
                TARGET_AUTOMATION_TOKEN,
                principalId,
                vaultId,
                "{\"revoked\":true}");
    }

    public void automationKeyPackageStored(
            @NonNull String ownerId,
            @NonNull String principalId,
            @NonNull String vaultId,
            @NonNull String vaultKeyId,
            @NonNull String keyAlgorithm) {
        appendAutomation(
                ownerId,
                ownerId,
                AuditEventType.AUTOMATION_KEY_PACKAGE_STORED,
                TARGET_KEY_PACKAGE,
                principalId,
                vaultId,
                safeKeyPackageDetails(vaultKeyId, keyAlgorithm));
    }

    public void recoveryEnrollmentCreated(
            @NonNull String username, @NonNull String enrollmentId, long generation) {
        appendRecoveryEnrollment(
                username,
                username,
                AuditEventType.RECOVERY_ENROLLMENT_CREATED,
                enrollmentId,
                generation,
                "PENDING");
    }

    public void recoveryEnrollmentCommitted(
            @NonNull String username, @NonNull String enrollmentId, long generation) {
        appendRecoveryEnrollment(
                username,
                username,
                AuditEventType.RECOVERY_ENROLLMENT_COMMITTED,
                enrollmentId,
                generation,
                "ACTIVE");
    }

    public void recoveryKeyPackageStored(
            @NonNull String username,
            @NonNull String actorId,
            @NonNull String enrollmentId,
            @NonNull String vaultId,
            long generation,
            @NonNull String vaultKeyId,
            @NonNull String keyAlgorithm) {
        auditEvents.append(
                new StoredAuditEvent(
                        UUID.randomUUID().toString(),
                        username,
                        actorId,
                        AuditEventType.RECOVERY_KEY_PACKAGE_STORED.name(),
                        TARGET_KEY_PACKAGE,
                        enrollmentId,
                        vaultId,
                        null,
                        OUTCOME_SUCCESS,
                        "{\"generation\":"
                                + generation
                                + ",\"vaultKeyId\":\""
                                + escapeJson(vaultKeyId)
                                + "\",\"keyAlgorithm\":\""
                                + escapeJson(keyAlgorithm)
                                + "\"}",
                        clock.instant()));
    }

    public void recoveryCompleted(
            @NonNull String username,
            @NonNull String deviceId,
            @NonNull String authority,
            int recoveredVaults,
            int pendingVaults) {
        auditEvents.append(
                new StoredAuditEvent(
                        UUID.randomUUID().toString(),
                        username,
                        username,
                        AuditEventType.RECOVERY_COMPLETED.name(),
                        TARGET_RECOVERY_SESSION,
                        deviceId,
                        null,
                        null,
                        OUTCOME_SUCCESS,
                        "{\"authority\":\""
                                + escapeJson(authority)
                                + "\",\"recoveredVaults\":"
                                + recoveredVaults
                                + ",\"pendingVaults\":"
                                + pendingVaults
                                + "}",
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

    private void appendAutomation(
            @NonNull String ownerId,
            @NonNull String actorId,
            @NonNull AuditEventType eventType,
            @NonNull String targetType,
            @NonNull String targetId,
            @Nullable String vaultId,
            @NonNull String details) {
        auditEvents.append(
                new StoredAuditEvent(
                        UUID.randomUUID().toString(),
                        ownerId,
                        actorId,
                        eventType.name(),
                        targetType,
                        targetId,
                        vaultId,
                        null,
                        OUTCOME_SUCCESS,
                        details,
                        clock.instant()));
    }

    private void appendRecoveryEnrollment(
            @NonNull String ownerId,
            @NonNull String actorId,
            @NonNull AuditEventType eventType,
            @NonNull String enrollmentId,
            long generation,
            @NonNull String state) {
        auditEvents.append(
                new StoredAuditEvent(
                        UUID.randomUUID().toString(),
                        ownerId,
                        actorId,
                        eventType.name(),
                        TARGET_RECOVERY_ENROLLMENT,
                        enrollmentId,
                        null,
                        null,
                        OUTCOME_SUCCESS,
                        "{\"generation\":"
                                + generation
                                + ",\"state\":\""
                                + escapeJson(state)
                                + "\"}",
                        clock.instant()));
    }

    private static @NonNull String safeRecordDetails(@NonNull String secretType, boolean deleted) {
        return "{\"secretType\":\"" + escapeJson(secretType) + "\",\"deleted\":" + deleted + "}";
    }

    private static @NonNull String safeKeyPackageDetails(
            @NonNull String vaultKeyId, @NonNull String keyAlgorithm) {
        return "{\"vaultKeyId\":\""
                + escapeJson(vaultKeyId)
                + "\",\"keyAlgorithm\":\""
                + escapeJson(keyAlgorithm)
                + "\"}";
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
