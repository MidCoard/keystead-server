package top.focess.keystead.server.vault;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.server.audit.AuditService;
import top.focess.keystead.server.identity.UserRepository;

@Service
class VaultMemberService {
    private final VaultAccessGuard access;
    private final VaultMemberRepository members;
    private final UserRepository users;
    private final VaultKeyPackageRepository keyPackages;
    private final VaultKeyLifecycleService lifecycle;
    private final AuditService audit;
    private final Clock clock;

    VaultMemberService(
            @NonNull VaultAccessGuard access,
            @NonNull VaultMemberRepository members,
            @NonNull UserRepository users,
            @NonNull VaultKeyPackageRepository keyPackages,
            @NonNull VaultKeyLifecycleService lifecycle,
            @NonNull AuditService audit,
            @NonNull Clock clock) {
        this.access = access;
        this.members = members;
        this.users = users;
        this.keyPackages = keyPackages;
        this.lifecycle = lifecycle;
        this.audit = audit;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    @NonNull List<VaultMemberResponse> list(@NonNull String actor, @NonNull String vaultId) {
        access.requireActiveMember(actor, vaultId);
        return members.findAllForVault(vaultId).stream()
                .map(VaultMemberEntity::toStored)
                .map(VaultMemberResponse::from)
                .toList();
    }

    @Transactional
    void invite(
            @NonNull String actor,
            @NonNull String vaultId,
            @NonNull String userId,
            @NonNull VaultMemberRequest request) {
        String ownerId = access.requireMemberManagerAndResolveOwner(actor, vaultId);
        if (request.role() == VaultMemberRole.OWNER || !users.exists(userId))
            throw new VaultNotFoundException("Vault does not exist");
        Instant now = clock.instant();
        StoredVaultMember previous = members.find(vaultId, userId).orElse(null);
        if (previous != null
                && (previous.role() == VaultMemberRole.OWNER
                        || previous.state() == VaultMemberState.ACTIVE
                        || previous.state() == VaultMemberState.ACCEPTED_PENDING_KEY)) {
            throw new VaultNotFoundException("Vault does not exist");
        }
        if (previous != null
                && previous.state() == VaultMemberState.INVITED
                && previous.role() == request.role()) {
            return;
        }
        Instant created =
                previous == null || previous.state() == VaultMemberState.REMOVED
                        ? now
                        : previous.createdAt();
        members.saveAndFlush(
                VaultMemberEntity.from(
                        new StoredVaultMember(
                                vaultId,
                                userId,
                                request.role(),
                                VaultMemberState.INVITED,
                                created,
                                now)));
        audit.vaultMemberInvited(ownerId, actor, vaultId, userId, request.role().name());
    }

    @Transactional
    void accept(@NonNull String userId, @NonNull String vaultId) {
        StoredVaultMember member =
                members.find(vaultId, userId)
                        .orElseThrow(() -> new VaultNotFoundException("Vault does not exist"));
        if (member.role() == VaultMemberRole.OWNER) {
            throw new VaultNotFoundException("Vault does not exist");
        }
        if (member.state() == VaultMemberState.ACCEPTED_PENDING_KEY) {
            return;
        }
        if (member.state() != VaultMemberState.INVITED) {
            throw new VaultNotFoundException("Vault does not exist");
        }
        members.saveAndFlush(
                VaultMemberEntity.from(
                        new StoredVaultMember(
                                vaultId,
                                userId,
                                member.role(),
                                VaultMemberState.ACCEPTED_PENDING_KEY,
                                member.createdAt(),
                                clock.instant())));
        audit.vaultMemberAccepted(access.resolveOwner(vaultId), userId, vaultId, userId);
    }

    @Transactional
    void decline(@NonNull String userId, @NonNull String vaultId) {
        StoredVaultMember member =
                members.find(vaultId, userId)
                        .orElseThrow(() -> new VaultNotFoundException("Vault does not exist"));
        if (member.role() == VaultMemberRole.OWNER || member.state() == VaultMemberState.ACTIVE) {
            throw new VaultNotFoundException("Vault does not exist");
        }
        if (member.state() == VaultMemberState.REMOVED) {
            return;
        }
        members.saveAndFlush(
                VaultMemberEntity.from(
                        new StoredVaultMember(
                                vaultId,
                                userId,
                                member.role(),
                                VaultMemberState.REMOVED,
                                member.createdAt(),
                                clock.instant())));
        audit.vaultMemberDeclined(access.resolveOwner(vaultId), userId, vaultId, userId);
    }

    @Transactional
    void changeRole(
            @NonNull String actor,
            @NonNull String vaultId,
            @NonNull String userId,
            @NonNull VaultMemberRequest request) {
        String ownerId = access.requireMemberManagerAndResolveOwner(actor, vaultId);
        StoredVaultMember member =
                members.find(vaultId, userId)
                        .orElseThrow(() -> new VaultNotFoundException("Vault does not exist"));
        if (member.role() == VaultMemberRole.OWNER || request.role() == VaultMemberRole.OWNER)
            throw new VaultNotFoundException("Vault does not exist");
        VaultMemberRole fromRole = member.role();
        members.saveAndFlush(
                VaultMemberEntity.from(
                        new StoredVaultMember(
                                vaultId,
                                userId,
                                request.role(),
                                member.state(),
                                member.createdAt(),
                                clock.instant())));
        audit.vaultMemberRoleChanged(
                ownerId, actor, vaultId, userId, fromRole.name(), request.role().name());
    }

    @Transactional
    void remove(@NonNull String actor, @NonNull String vaultId, @NonNull String userId) {
        String ownerId = access.requireMemberManagerAndResolveOwner(actor, vaultId);
        StoredVaultMember member =
                members.find(vaultId, userId)
                        .orElseThrow(() -> new VaultNotFoundException("Vault does not exist"));
        if (member.role() == VaultMemberRole.OWNER)
            throw new VaultNotFoundException("Vault does not exist");
        boolean requiresRotation =
                member.state() == VaultMemberState.ACTIVE
                        || keyPackages.countCurrentForRecipient(ownerId, vaultId, userId) > 0;
        keyPackages.deleteForRecipient(ownerId, vaultId, userId);
        Instant now = clock.instant();
        members.saveAndFlush(
                VaultMemberEntity.from(
                        new StoredVaultMember(
                                vaultId,
                                userId,
                                member.role(),
                                VaultMemberState.REMOVED,
                                member.createdAt(),
                                now)));
        audit.vaultMemberRemoved(ownerId, actor, vaultId, userId);
        if (requiresRotation) {
            lifecycle.requireRotation(ownerId, actor, vaultId, "MEMBER_REMOVED", userId, now);
        }
    }
}
