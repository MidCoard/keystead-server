package top.focess.keystead.server.auth;

import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;

interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, String> {

    default @NonNull Optional<StoredRefreshToken> find(@NonNull String tokenHash) {
        return findById(tokenHash).map(RefreshTokenEntity::toStored);
    }

    default void upsert(@NonNull StoredRefreshToken token) {
        saveAndFlush(RefreshTokenEntity.from(token));
    }
}
