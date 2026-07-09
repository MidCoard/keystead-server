package top.focess.keystead.server.vault;

import jakarta.persistence.EntityManager;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
class VaultRepositoryWritesImpl implements VaultRepositoryWrites {

    private final EntityManager entityManager;

    VaultRepositoryWritesImpl(@NonNull EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public void insert(@NonNull StoredVault vault) {
        entityManager.persist(VaultEntity.from(vault));
        entityManager.flush();
    }

    @Override
    public void update(@NonNull StoredVault vault) {
        entityManager.merge(VaultEntity.from(vault));
        entityManager.flush();
    }
}
