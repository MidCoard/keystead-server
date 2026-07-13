package top.focess.keystead.server.vault;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface VaultMemberRepository extends JpaRepository<VaultMemberEntity, VaultMemberEntityId> {
    @org.springframework.data.jpa.repository.Query(
            "select m from VaultMemberEntity m where m.id.vaultId = :vaultId order by m.id.userId")
    @NonNull List<VaultMemberEntity> findAllForVault(
            @org.springframework.data.repository.query.Param("vaultId") @NonNull String vaultId);

    @Query(
            """
            select m from VaultMemberEntity m
             where m.id.userId = :userId
               and m.state <> top.focess.keystead.server.vault.VaultMemberState.REMOVED
             order by m.id.vaultId
            """)
    @NonNull List<VaultMemberEntity> findAllForUser(@Param("userId") @NonNull String userId);

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
