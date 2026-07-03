package top.focess.keystead.server.vault;

import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

@Component
public class VaultAccessGuard {

    private final VaultRepository vaults;

    VaultAccessGuard(@NonNull VaultRepository vaults) {
        this.vaults = vaults;
    }

    public void requireOwnedVault(@NonNull String ownerId, @NonNull String vaultId) {
        if (!vaults.exists(ownerId, vaultId)) {
            throw new VaultNotFoundException("Vault does not exist");
        }
    }

    @NonNull Optional<StoredVault> findOwnedVaultOrRejectTakenId(
            @NonNull String ownerId, @NonNull String vaultId) {
        Optional<StoredVault> existing = vaults.find(ownerId, vaultId);
        if (existing.isEmpty() && vaults.existsGlobally(vaultId)) {
            throw new VaultNotFoundException("Vault does not exist");
        }
        return existing;
    }
}
