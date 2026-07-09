package top.focess.keystead.server.record;

import jakarta.persistence.EntityManager;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
class EncryptedRecordRepositoryWritesImpl implements EncryptedRecordRepositoryWrites {

    private final EntityManager entityManager;

    EncryptedRecordRepositoryWritesImpl(@NonNull EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public void insert(@NonNull StoredEncryptedRecord record) {
        entityManager.persist(EncryptedRecordEntity.from(record));
        entityManager.flush();
    }

    @Override
    public void update(@NonNull StoredEncryptedRecord record) {
        entityManager.merge(EncryptedRecordEntity.from(record));
        entityManager.flush();
    }
}
