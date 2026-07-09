package top.focess.keystead.server.identity;

import jakarta.persistence.EntityManager;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
class DeviceChallengeRepositoryWritesImpl implements DeviceChallengeRepositoryWrites {

    private final EntityManager entityManager;

    DeviceChallengeRepositoryWritesImpl(@NonNull EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public void insert(@NonNull StoredDeviceChallenge challenge) {
        entityManager.persist(DeviceChallengeEntity.from(challenge));
        entityManager.flush();
    }
}
