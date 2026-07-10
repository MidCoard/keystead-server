package top.focess.keystead.server.vault;

import java.time.Instant;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;

interface VaultMemberRepository extends JpaRepository<VaultMemberEntity, VaultMemberEntityId> {
    default @NonNull Optional<StoredVaultMember> find(
            @NonNull String vaultId, @NonNull String userId) {
        return findById(new VaultMemberEntityId(vaultId, userId)).map(VaultMemberEntity::toStored);
    }

    default void insertOwner(
            @NonNull String vaultId, @NonNull String ownerId, @NonNull Instant now) {
        saveAndFlush(
                VaultMemberEntity.from(
                        new StoredVaultMember(
                                vaultId,
                                ownerId,
                                VaultMemberRole.OWNER,
                                VaultMemberState.ACTIVE,
                                now,
                                now)));
    }

    default @NonNull Optional<StoredVaultMember> findActive(
            @NonNull String vaultId, @NonNull String userId) {
        return find(vaultId, userId).filter(member -> member.state() == VaultMemberState.ACTIVE);
    }
}
