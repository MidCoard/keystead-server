package top.focess.keystead.server.auth;

import jakarta.persistence.EntityManager;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
class RefreshTokenRepositoryWritesImpl implements RefreshTokenRepositoryWrites {

    private final EntityManager entityManager;

    RefreshTokenRepositoryWritesImpl(@NonNull EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public void insert(@NonNull StoredRefreshToken token) {
        entityManager.persist(RefreshTokenEntity.from(token));
        entityManager.flush();
    }

    @Override
    public void update(@NonNull StoredRefreshToken token) {
        entityManager.merge(RefreshTokenEntity.from(token));
        entityManager.flush();
    }
}
