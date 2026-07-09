package top.focess.keystead.server.vault;

import jakarta.persistence.EntityManager;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
class VaultKeyPackageRepositoryWritesImpl implements VaultKeyPackageRepositoryWrites {

    private final EntityManager entityManager;

    VaultKeyPackageRepositoryWritesImpl(@NonNull EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public void insert(@NonNull StoredVaultKeyPackage keyPackage) {
        entityManager.persist(VaultKeyPackageEntity.from(keyPackage));
        entityManager.flush();
    }

    @Override
    public void update(@NonNull StoredVaultKeyPackage keyPackage) {
        entityManager.merge(VaultKeyPackageEntity.from(keyPackage));
        entityManager.flush();
    }
}
