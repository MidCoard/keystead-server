package top.focess.keystead.server.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.Iterator;
import java.util.Locale;
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

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Set<String> ALLOWED_OUTCOMES = Set.of("SUCCESS", "FAILURE", "CONFLICT");
    private static final Set<String> ALLOWED_TARGET_TYPES =
            Set.of(
                    "auth",
                    "device",
                    "key_package",
                    "record",
                    "recovery_enrollment",
                    "recovery_session",
                    "automation_principal",
                    "automation_token");
    private static final Set<String> FORBIDDEN_DETAIL_KEYS =
            Set.of(
                    "encryptedprofile",
                    "metadata",
                    "envelope",
                    "encryptedpayload",
                    "wrappedvaultkey",
                    "password",
                    "token",
                    "refreshtoken",
                    "deviceprivatekey",
                    "accountcredential",
                    "encryptedprivatekey",
                    "encryptedvaultkey",
                    "wrappingpublickey");

    public StoredAuditEvent {
        requireNotBlank(eventId, "eventId");
        requireNotBlank(ownerId, "ownerId");
        requireNotBlank(actorId, "actorId");
        requireNotBlank(eventType, "eventType");
        AuditEventType type;
        try {
            type = AuditEventType.valueOf(eventType);
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
        requireEventShape(type, targetType, vaultId, revision, outcome);
        requireNotBlank(details, "details");
        requireJsonObjectDetails(details);
        Objects.requireNonNull(createdAt, "createdAt");
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }

    private static void requireJsonObjectDetails(@NonNull String details) {
        try {
            JsonNode node = JSON.readTree(details);
            if (node == null || !node.isObject()) {
                throw new IllegalArgumentException("Audit details must be a JSON object");
            }
            requireNoForbiddenDetailKeys(node);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Audit details must be a JSON object", e);
        }
    }

    private static void requireNoForbiddenDetailKeys(@NonNull JsonNode node) {
        Iterator<String> fieldNames = node.fieldNames();
        while (fieldNames.hasNext()) {
            String fieldName = fieldNames.next();
            if (FORBIDDEN_DETAIL_KEYS.contains(normalizedDetailKey(fieldName))) {
                throw new IllegalArgumentException("Audit details contain forbidden field");
            }
            requireNoForbiddenDetailKeys(node.get(fieldName));
        }
        for (JsonNode child : node) {
            requireNoForbiddenDetailKeys(child);
        }
    }

    private static @NonNull String normalizedDetailKey(@NonNull String key) {
        StringBuilder normalized = new StringBuilder(key.length());
        key.toLowerCase(Locale.ROOT)
                .chars()
                .filter(Character::isLetterOrDigit)
                .forEach(character -> normalized.append((char) character));
        return normalized.toString();
    }

    private static void requireEventShape(
            @NonNull AuditEventType eventType,
            @NonNull String targetType,
            @Nullable String vaultId,
            @Nullable Long revision,
            @NonNull String outcome) {
        switch (eventType) {
            case RECORD_STORED, RECORD_DELETED -> {
                requireShape(targetType, "record", outcome, "SUCCESS");
                requireVaultAndRevision(vaultId, revision);
            }
            case RECORD_REVISION_CONFLICT -> {
                requireShape(targetType, "record", outcome, "CONFLICT");
                requireVaultAndRevision(vaultId, revision);
            }
            case KEY_PACKAGE_STORED -> {
                requireShape(targetType, "key_package", outcome, "SUCCESS");
                requireVaultWithoutRevision(vaultId, revision);
            }
            case DEVICE_REVOKED -> {
                requireShape(targetType, "device", outcome, "SUCCESS");
                requireNoVaultOrRevision(vaultId, revision);
            }
            case LOGIN_FAILED -> {
                requireShape(targetType, "auth", outcome, "FAILURE");
                requireNoVaultOrRevision(vaultId, revision);
            }
            case AUTOMATION_PRINCIPAL_STORED, AUTOMATION_PRINCIPAL_REVOKED -> {
                requireShape(targetType, "automation_principal", outcome, "SUCCESS");
                requireVaultWithoutRevision(vaultId, revision);
            }
            case AUTOMATION_TOKEN_ISSUED, AUTOMATION_TOKEN_REVOKED -> {
                requireShape(targetType, "automation_token", outcome, "SUCCESS");
                requireVaultWithoutRevision(vaultId, revision);
            }
            case AUTOMATION_KEY_PACKAGE_STORED -> {
                requireShape(targetType, "key_package", outcome, "SUCCESS");
                requireVaultWithoutRevision(vaultId, revision);
            }
            case RECOVERY_ENROLLMENT_CREATED, RECOVERY_ENROLLMENT_COMMITTED -> {
                requireShape(targetType, "recovery_enrollment", outcome, "SUCCESS");
                requireNoVaultOrRevision(vaultId, revision);
            }
            case RECOVERY_KEY_PACKAGE_STORED -> {
                requireShape(targetType, "key_package", outcome, "SUCCESS");
                requireVaultWithoutRevision(vaultId, revision);
            }
            case RECOVERY_COMPLETED -> {
                requireShape(targetType, "recovery_session", outcome, "SUCCESS");
                requireNoVaultOrRevision(vaultId, revision);
            }
        }
    }

    private static void requireShape(
            @NonNull String actualTargetType,
            @NonNull String expectedTargetType,
            @NonNull String actualOutcome,
            @NonNull String expectedOutcome) {
        if (!actualTargetType.equals(expectedTargetType)) {
            throw new IllegalArgumentException("Audit target type does not match event type");
        }
        if (!actualOutcome.equals(expectedOutcome)) {
            throw new IllegalArgumentException("Audit outcome does not match event type");
        }
    }

    private static void requireVaultAndRevision(@Nullable String vaultId, @Nullable Long revision) {
        if (vaultId == null || revision == null) {
            throw new IllegalArgumentException("Audit event requires vault and revision");
        }
    }

    private static void requireVaultWithoutRevision(
            @Nullable String vaultId, @Nullable Long revision) {
        if (vaultId == null) {
            throw new IllegalArgumentException("Audit event requires vault");
        }
        if (revision != null) {
            throw new IllegalArgumentException("Audit event must not carry revision");
        }
    }

    private static void requireNoVaultOrRevision(
            @Nullable String vaultId, @Nullable Long revision) {
        if (vaultId != null || revision != null) {
            throw new IllegalArgumentException("Audit event must not carry vault or revision");
        }
    }
}
