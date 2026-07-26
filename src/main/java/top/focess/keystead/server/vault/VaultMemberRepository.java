package top.focess.keystead.server.vault;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface VaultMemberRepository extends JpaRepository<VaultMemberEntity, VaultMemberEntityId> {
    @org.springframework.data.jpa.repository.Query(
            "select m from VaultMemberEntity m where m.id.fingerprint = :fingerprint order by m.id.userId")
    @NonNull List<VaultMemberEntity> findAllForVault(
            @org.springframework.data.repository.query.Param("fingerprint")
                    @NonNull String fingerprint);

    @Query(
            """
            select m from VaultMemberEntity m
             where m.id.userId = :userId
               and m.state <> top.focess.keystead.server.vault.VaultMemberState.REMOVED
             order by m.id.fingerprint
            """)
    @NonNull List<VaultMemberEntity> findAllForUser(@Param("userId") @NonNull String userId);

    default @NonNull Optional<StoredVaultMember> find(
            @NonNull String fingerprint, @NonNull String userId) {
        return findById(new VaultMemberEntityId(fingerprint, userId))
                .map(VaultMemberEntity::toStored);
    }

    default void insertOwner(
            @NonNull String fingerprint, @NonNull String ownerId, @NonNull Instant now) {
        saveAndFlush(
                VaultMemberEntity.from(
                        new StoredVaultMember(
                                fingerprint,
                                ownerId,
                                VaultMemberRole.OWNER,
                                VaultMemberState.ACTIVE,
                                now,
                                now)));
    }

    default @NonNull Optional<StoredVaultMember> findActive(
            @NonNull String fingerprint, @NonNull String userId) {
        return find(fingerprint, userId)
                .filter(member -> member.state() == VaultMemberState.ACTIVE);
    }

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
            """
            update VaultMemberEntity m
               set m.state = top.focess.keystead.server.vault.VaultMemberState.ACTIVE,
                   m.updatedAt = :updatedAt
             where m.id.fingerprint = :fingerprint
               and m.id.userId = :userId
               and m.state = top.focess.keystead.server.vault.VaultMemberState.ACCEPTED_PENDING_KEY
            """)
    int activatePending(
            @Param("fingerprint") @NonNull String fingerprint,
            @Param("userId") @NonNull String userId,
            @Param("updatedAt") @NonNull Instant updatedAt);
}
