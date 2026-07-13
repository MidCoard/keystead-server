package top.focess.keystead.server.vault;

import jakarta.validation.Validator;
import java.time.Clock;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class VaultKeyRotationService {
    private final VaultAccessGuard accessGuard;
    private final VaultKeyStateRepository keyStates;
    private final Clock clock;
    private final Validator validator;

    VaultKeyRotationService(
            @NonNull VaultAccessGuard accessGuard,
            @NonNull VaultKeyStateRepository keyStates,
            @NonNull Clock clock,
            @NonNull Validator validator) {
        this.accessGuard = accessGuard;
        this.keyStates = keyStates;
        this.clock = clock;
        this.validator = validator;
    }

    @Transactional
    void rotate(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull VaultKeyRotationRequest request) {
        accessGuard.requireOwnedVault(ownerId, vaultId);
        if (!validator.validate(request).isEmpty())
            throw new IllegalArgumentException("vaultKeyId is invalid");
        VaultEntityId id = new VaultEntityId(ownerId, vaultId);
        Optional<VaultKeyStateEntity> existing = keyStates.findById(id);
        VaultKeyStateEntity state = existing.orElseGet(VaultKeyStateEntity::new);
        state.id = id;
        state.currentVaultKeyId = request.vaultKeyId();
        state.lifecycleState = VaultKeyLifecycleState.STABLE;
        state.lifecycleVersion = existing.isPresent() ? state.lifecycleVersion + 1L : 1L;
        state.pendingGenerationId = null;
        state.updatedAt = clock.instant();
        keyStates.save(state);
    }

    public void requireCurrentOrLegacy(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String vaultKeyId) {
        keyStates
                .findById(new VaultEntityId(ownerId, vaultId))
                .map(state -> state.currentVaultKeyId)
                .filter(currentVaultKeyId -> !currentVaultKeyId.equals(vaultKeyId))
                .ifPresent(
                        value -> {
                            throw new InvalidVaultKeyPackageRequestException(
                                    "Vault key package uses a stale vault key id");
                        });
    }
}
