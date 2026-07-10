package top.focess.keystead.server.vault;

import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

@Component
public class VaultAccessGuard {

    private final VaultRepository vaults;
    private final VaultMemberRepository members;

    VaultAccessGuard(@NonNull VaultRepository vaults, @NonNull VaultMemberRepository members) {
        this.vaults = vaults;
        this.members = members;
    }

    public void requireActiveMember(@NonNull String userId, @NonNull String vaultId) {
        activeMemberOrThrow(userId, vaultId);
    }

    public @NonNull String requireActiveMemberAndResolveOwner(
            @NonNull String userId, @NonNull String vaultId) {
        activeMemberOrThrow(userId, vaultId);
        return vaults.findGlobally(vaultId)
                .orElseThrow(() -> new VaultNotFoundException("Vault does not exist"))
                .ownerId();
    }

    public void requireWritableMember(@NonNull String userId, @NonNull String vaultId) {
        if (!activeMemberOrThrow(userId, vaultId).role().canWriteRecords()) {
            throw new VaultNotFoundException("Vault does not exist");
        }
    }

    public void requireMemberManager(@NonNull String userId, @NonNull String vaultId) {
        if (!activeMemberOrThrow(userId, vaultId).role().canManageMembers()) {
            throw new VaultNotFoundException("Vault does not exist");
        }
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

    private @NonNull StoredVaultMember activeMemberOrThrow(
            @NonNull String userId, @NonNull String vaultId) {
        return members.findActive(vaultId, userId)
                .orElseThrow(() -> new VaultNotFoundException("Vault does not exist"));
    }
}
