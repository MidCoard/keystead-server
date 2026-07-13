package top.focess.keystead.server.vault;

import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import top.focess.keystead.server.audit.AuditService;

@Service
class VaultKeyLifecycleService {

    private final VaultKeyStateRepository keyStates;
    private final AuditService audit;

    VaultKeyLifecycleService(
            @NonNull VaultKeyStateRepository keyStates, @NonNull AuditService audit) {
        this.keyStates = keyStates;
        this.audit = audit;
    }

    void requireRotation(
            @NonNull String ownerId,
            @NonNull String actorId,
            @NonNull String vaultId,
            @NonNull String reason,
            @NonNull String subjectId,
            @NonNull Instant now) {
        if (keyStates.markRotationRequired(ownerId, vaultId, now) == 1) {
            audit.vaultRotationRequired(ownerId, actorId, vaultId, reason, subjectId);
        }
    }
}
