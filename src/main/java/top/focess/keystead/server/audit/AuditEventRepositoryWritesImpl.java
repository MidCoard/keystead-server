package top.focess.keystead.server.audit;

import jakarta.persistence.EntityManager;
import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
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
    public void append(
            @NonNull StoredAuditEvent event,
            @Nullable String correlationId,
            @Nullable String signature) {
        entityManager.persist(AuditEventEntity.from(event, correlationId, signature));
        entityManager.flush();
    }

    @Override
    public int deleteOlderThan(@NonNull String ownerId, @NonNull Instant cutoff) {
        return entityManager
                .createQuery(
                        "delete from AuditEventEntity e where e.ownerId = :ownerId and e.createdAt < :cutoff")
                .setParameter("ownerId", ownerId)
                .setParameter("cutoff", cutoff)
                .executeUpdate();
    }
}
