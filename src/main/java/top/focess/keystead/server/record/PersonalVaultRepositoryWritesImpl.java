package top.focess.keystead.server.record;

import jakarta.persistence.EntityManager;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
class PersonalVaultRepositoryWritesImpl implements PersonalVaultRepositoryWrites {
    private final EntityManager entityManager;

    PersonalVaultRepositoryWritesImpl(@NonNull EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public void insert(@NonNull PersonalVaultEntity entity) {
        entityManager.persist(entity);
        entityManager.flush();
    }
}
