package top.focess.keystead.server.identity;

import jakarta.persistence.EntityManager;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
class DeviceRepositoryWritesImpl implements DeviceRepositoryWrites {

    private final EntityManager entityManager;

    DeviceRepositoryWritesImpl(@NonNull EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public void insert(@NonNull StoredDevice device) {
        entityManager.persist(DeviceEntity.from(device));
        entityManager.flush();
    }

    @Override
    public void update(@NonNull StoredDevice device) {
        entityManager.merge(DeviceEntity.from(device));
        entityManager.flush();
    }
}
