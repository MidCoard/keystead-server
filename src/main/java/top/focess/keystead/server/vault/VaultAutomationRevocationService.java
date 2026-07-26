package top.focess.keystead.server.vault;

import java.time.Instant;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class VaultAutomationRevocationService {

    private final VaultKeyLifecycleService lifecycle;

    VaultAutomationRevocationService(@NonNull VaultKeyLifecycleService lifecycle) {
        this.lifecycle = lifecycle;
    }

    @Transactional
    public void requireRotation(
            @NonNull String ownerId,
            @NonNull String principalId,
            @NonNull List<String> fingerprints,
            @NonNull Instant now) {
        for (String fingerprint : fingerprints.stream().distinct().toList()) {
            lifecycle.requireRotation(
                    ownerId, ownerId, fingerprint, "AUTOMATION_REVOKED", principalId, now);
        }
    }
}
