package top.focess.keystead.server.vaultaccess;

import jakarta.persistence.EntityManager;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
class VaultAccessRequestRepositoryWritesImpl implements VaultAccessRequestRepositoryWrites {
    private final EntityManager entityManager;

    VaultAccessRequestRepositoryWritesImpl(@NonNull EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public void insert(@NonNull VaultAccessRequestEntity entity) {
        entityManager.persist(entity);
        entityManager.flush();
    }
}
