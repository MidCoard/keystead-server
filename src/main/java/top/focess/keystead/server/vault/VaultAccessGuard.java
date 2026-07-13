package top.focess.keystead.server.vault;

import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

@Component
public class VaultAccessGuard {

    private final VaultRepository vaults;
    private final VaultMemberRepository members;
    private final VaultKeyStateRepository keyStates;

    VaultAccessGuard(
            @NonNull VaultRepository vaults,
            @NonNull VaultMemberRepository members,
            @NonNull VaultKeyStateRepository keyStates) {
        this.vaults = vaults;
        this.members = members;
        this.keyStates = keyStates;
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

    public void requireStableForWrite(@NonNull String ownerId, @NonNull String vaultId) {
        VaultKeyLifecycleState state =
                keyStates
                        .findById(new VaultEntityId(ownerId, vaultId))
                        .map(value -> value.lifecycleState)
                        .orElse(VaultKeyLifecycleState.STABLE);
        if (state != VaultKeyLifecycleState.STABLE) {
            throw new VaultLifecycleConflictException(state);
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
