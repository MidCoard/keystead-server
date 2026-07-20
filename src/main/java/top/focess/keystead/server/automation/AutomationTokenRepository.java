package top.focess.keystead.server.automation;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface AutomationTokenRepository extends JpaRepository<AutomationTokenEntity, String> {

    default @NonNull Optional<AutomationToken> find(@NonNull String tokenHash) {
        return findById(tokenHash).map(AutomationTokenEntity::toStored);
    }

    default void persist(@NonNull AutomationToken token) {
        save(AutomationTokenEntity.from(token));
    }

    default @NonNull List<AutomationToken> list(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String principalId) {
        return findByOwnerIdAndVaultIdAndPrincipalIdOrderByCreatedAtDesc(
                        ownerId, vaultId, principalId)
                .stream()
                .map(AutomationTokenEntity::toStored)
                .toList();
    }

    default @NonNull Optional<AutomationToken> findByTokenId(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull String principalId,
            @NonNull String tokenId) {
        return findByOwnerIdAndVaultIdAndPrincipalIdAndTokenId(
                        ownerId, vaultId, principalId, tokenId)
                .map(AutomationTokenEntity::toStored);
    }

    List<AutomationTokenEntity> findByOwnerIdAndVaultIdAndPrincipalIdOrderByCreatedAtDesc(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String principalId);

    Optional<AutomationTokenEntity> findByOwnerIdAndVaultIdAndPrincipalIdAndTokenId(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull String principalId,
            @NonNull String tokenId);

    @Modifying
    @Query(
            """
            update AutomationTokenEntity t
               set t.lastUsedAt = :lastUsedAt
             where t.tokenHash = :tokenHash
               and t.revokedAt is null
               and t.expiresAt > :lastUsedAt
            """)
    int touchActive(
            @Param("tokenHash") @NonNull String tokenHash,
            @Param("lastUsedAt") @NonNull Instant lastUsedAt);

    @Modifying
    @Query(
            """
            update AutomationTokenEntity t
               set t.revokedAt = :revokedAt
             where t.ownerId = :ownerId
               and t.principalId = :principalId
               and t.revokedAt is null
            """)
    int revokeActiveForPrincipal(
            @Param("ownerId") @NonNull String ownerId,
            @Param("principalId") @NonNull String principalId,
            @Param("revokedAt") @NonNull Instant revokedAt);
}
