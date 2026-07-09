package top.focess.keystead.server.audit;

import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface AuditEventRepository
        extends JpaRepository<AuditEventEntity, String>, AuditEventRepositoryWrites {

    @Query(
            """
            select e
              from AuditEventEntity e
             where e.ownerId = :ownerId
             order by e.createdAt, e.eventId
            """)
    @NonNull List<AuditEventEntity> listEntitiesForOwner(@Param("ownerId") @NonNull String ownerId);

    default @NonNull List<StoredAuditEvent> listForOwner(@NonNull String ownerId) {
        return listEntitiesForOwner(ownerId).stream().map(AuditEventEntity::toStored).toList();
    }
}
