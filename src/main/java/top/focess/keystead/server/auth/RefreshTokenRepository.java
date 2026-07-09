package top.focess.keystead.server.auth;

import java.time.Instant;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, String> {

    default @NonNull Optional<StoredRefreshToken> find(@NonNull String tokenHash) {
        return findById(tokenHash).map(RefreshTokenEntity::toStored);
    }

    default void upsert(@NonNull StoredRefreshToken token) {
        saveAndFlush(RefreshTokenEntity.from(token));
    }

    @Modifying
    @Query(
            """
            update RefreshTokenEntity t
               set t.revokedAt = :revokedAt
             where t.username = :username
               and t.revokedAt is null
            """)
    void revokeAllForUsername(
            @Param("username") @NonNull String username,
            @Param("revokedAt") @NonNull Instant revokedAt);
}
