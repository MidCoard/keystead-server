package top.focess.keystead.server.identity;

import jakarta.persistence.EntityManager;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
class UserRepositoryWritesImpl implements UserRepositoryWrites {

    private final EntityManager entityManager;

    UserRepositoryWritesImpl(@NonNull EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public void insert(@NonNull StoredUser user) {
        entityManager.persist(UserEntity.from(user));
        entityManager.flush();
    }
}
