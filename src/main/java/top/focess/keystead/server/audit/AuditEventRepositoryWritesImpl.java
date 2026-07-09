package top.focess.keystead.server.audit;

import jakarta.persistence.EntityManager;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
class AuditEventRepositoryWritesImpl implements AuditEventRepositoryWrites {

    private final EntityManager entityManager;

    AuditEventRepositoryWritesImpl(@NonNull EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public void append(@NonNull StoredAuditEvent event) {
        entityManager.persist(AuditEventEntity.from(event));
        entityManager.flush();
    }
}
