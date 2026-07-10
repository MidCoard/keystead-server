package top.focess.keystead.server.identity;

import jakarta.persistence.EntityManager;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
class DeviceVaultSyncCursorRepositoryWritesImpl implements DeviceVaultSyncCursorRepositoryWrites {

    private final EntityManager entityManager;

    DeviceVaultSyncCursorRepositoryWritesImpl(@NonNull EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public void insert(@NonNull StoredDeviceVaultSyncCursor cursor) {
        entityManager.persist(DeviceVaultSyncCursorEntity.from(cursor));
        entityManager.flush();
    }

    @Override
    public void update(@NonNull StoredDeviceVaultSyncCursor cursor) {
        entityManager.merge(DeviceVaultSyncCursorEntity.from(cursor));
        entityManager.flush();
    }
}
