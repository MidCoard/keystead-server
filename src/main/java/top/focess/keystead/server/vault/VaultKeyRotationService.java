package top.focess.keystead.server.vault;

import jakarta.validation.Validator;
import java.time.Clock;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class VaultKeyRotationService {
    private final VaultAccessGuard accessGuard;
    private final VaultKeyRotationRepository rotations;
    private final Clock clock;
    private final Validator validator;

    VaultKeyRotationService(
            @NonNull VaultAccessGuard accessGuard,
            @NonNull VaultKeyRotationRepository rotations,
            @NonNull Clock clock,
            @NonNull Validator validator) {
        this.accessGuard = accessGuard;
        this.rotations = rotations;
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
        rotations.persist(
                new VaultKeyRotation(ownerId, vaultId, request.vaultKeyId(), clock.instant()));
    }

    public void requireCurrentOrLegacy(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String vaultKeyId) {
        rotations
                .find(ownerId, vaultId)
                .filter(rotation -> !rotation.vaultKeyId().equals(vaultKeyId))
                .ifPresent(
                        value -> {
                            throw new InvalidVaultKeyPackageRequestException(
                                    "Vault key package uses a stale vault key id");
                        });
    }
}
