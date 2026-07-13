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

    /**
     * Returns the append-only audit trail for one owner's vault.  The owner
     * predicate is intentionally retained even though vault ids are normally
     * opaque: callers must never be able to infer another user's audit data.
     */
    @Query(
            """
            select e
              from AuditEventEntity e
             where e.ownerId = :ownerId
               and e.vaultId = :vaultId
             order by e.createdAt, e.eventId
            """)
    @NonNull
    List<AuditEventEntity> listEntitiesForOwnerAndVault(
            @Param("ownerId") @NonNull String ownerId, @Param("vaultId") @NonNull String vaultId);

    default @NonNull List<StoredAuditEvent> listForOwnerAndVault(
            @NonNull String ownerId, @NonNull String vaultId) {
        return listEntitiesForOwnerAndVault(ownerId, vaultId).stream()
                .map(AuditEventEntity::toStored)
                .toList();
    }
}
