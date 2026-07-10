package top.focess.keystead.server.automation;

import java.time.Instant;
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
