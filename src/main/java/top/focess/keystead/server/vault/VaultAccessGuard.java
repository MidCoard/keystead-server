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

    public void requireActiveMember(@NonNull String userId, @NonNull String fingerprint) {
        activeMemberOrThrow(userId, fingerprint);
    }

    public void requireAcceptedOrActiveMember(@NonNull String userId, @NonNull String fingerprint) {
        StoredVaultMember member =
                members.find(fingerprint, userId)
                        .orElseThrow(() -> new VaultNotFoundException("Vault does not exist"));
        if (member.state() != VaultMemberState.ACCEPTED_PENDING_KEY
                && member.state() != VaultMemberState.ACTIVE) {
            throw new VaultNotFoundException("Vault does not exist");
        }
    }

    public @NonNull String requireActiveMemberAndResolveOwner(
            @NonNull String userId, @NonNull String fingerprint) {
        activeMemberOrThrow(userId, fingerprint);
        return vaults.findGlobally(fingerprint)
                .orElseThrow(() -> new VaultNotFoundException("Vault does not exist"))
                .ownerId();
    }

    public void requireWritableMember(@NonNull String userId, @NonNull String fingerprint) {
        if (!activeMemberOrThrow(userId, fingerprint).role().canWriteRecords()) {
            throw new VaultNotFoundException("Vault does not exist");
        }
    }

    public void requireMemberManager(@NonNull String userId, @NonNull String fingerprint) {
        if (!activeMemberOrThrow(userId, fingerprint).role().canManageMembers()) {
            throw new VaultNotFoundException("Vault does not exist");
        }
    }

    public @NonNull String requireMemberManagerAndResolveOwner(
            @NonNull String userId, @NonNull String fingerprint) {
        StoredVaultMember member = activeMemberOrThrow(userId, fingerprint);
        if (!member.role().canManageMembers()) {
            throw new VaultNotFoundException("Vault does not exist");
        }
        return resolveOwner(fingerprint);
    }

    public @NonNull String resolveOwner(@NonNull String fingerprint) {
        return vaults.findGlobally(fingerprint)
                .orElseThrow(() -> new VaultNotFoundException("Vault does not exist"))
                .ownerId();
    }

    public void requireOwnedVault(@NonNull String ownerId, @NonNull String fingerprint) {
        if (!vaults.exists(ownerId, fingerprint)) {
            throw new VaultNotFoundException("Vault does not exist");
        }
    }

    public void requireStableForWrite(@NonNull String ownerId, @NonNull String fingerprint) {
        VaultKeyLifecycleState state =
                keyStates
                        .findById(new VaultEntityId(ownerId, fingerprint))
                        .map(value -> value.lifecycleState)
                        .orElse(VaultKeyLifecycleState.STABLE);
        if (state != VaultKeyLifecycleState.STABLE) {
            throw new VaultLifecycleConflictException(state);
        }
    }

    @NonNull Optional<StoredVault> findOwnedVaultOrRejectTakenId(
            @NonNull String ownerId, @NonNull String fingerprint) {
        Optional<StoredVault> existing = vaults.find(ownerId, fingerprint);
        if (existing.isEmpty() && vaults.existsGlobally(fingerprint)) {
            throw new VaultNotFoundException("Vault does not exist");
        }
        return existing;
    }

    private @NonNull StoredVaultMember activeMemberOrThrow(
            @NonNull String userId, @NonNull String fingerprint) {
        return members.findActive(fingerprint, userId)
                .orElseThrow(() -> new VaultNotFoundException("Vault does not exist"));
    }
}
