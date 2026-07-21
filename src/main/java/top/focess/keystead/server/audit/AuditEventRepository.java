package top.focess.keystead.server.audit;

import java.time.Instant;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.data.domain.Pageable;
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
     * Returns the append-only audit trail for one owner's vault. The owner predicate is
     * intentionally retained even though vault ids are normally opaque: callers must never be able
     * to infer another user's audit data.
     */
    @Query(
            """
            select e
              from AuditEventEntity e
             where e.ownerId = :ownerId
               and e.vaultId = :vaultId
             order by e.createdAt, e.eventId
            """)
    @NonNull List<AuditEventEntity> listEntitiesForOwnerAndVault(
            @Param("ownerId") @NonNull String ownerId, @Param("vaultId") @NonNull String vaultId);

    default @NonNull List<StoredAuditEvent> listForOwnerAndVault(
            @NonNull String ownerId, @NonNull String vaultId) {
        return listEntitiesForOwnerAndVault(ownerId, vaultId).stream()
                .map(AuditEventEntity::toStored)
                .toList();
    }

    /**
     * First page of one owner's trail, newest-first. The optional {@code vaultId} filters to a
     * single vault; {@code null} returns events across all of the owner's vaults. The owner
     * predicate is always applied so callers cannot page through another user's trail.
     */
    @Query(
            """
            select e
              from AuditEventEntity e
             where e.ownerId = :ownerId
               and (:vaultId is null or e.vaultId = :vaultId)
             order by e.createdAt desc, e.eventId desc
            """)
    @NonNull List<AuditEventEntity> pageFirstEntities(
            @Param("ownerId") @NonNull String ownerId,
            @Param("vaultId") @Nullable String vaultId,
            @NonNull Pageable pageable);

    default @NonNull List<AuditEventEntity> pageFirst(
            @NonNull String ownerId, @Nullable String vaultId, int limit) {
        return pageFirstEntities(ownerId, vaultId, Pageable.ofSize(Math.max(1, limit)));
    }

    /**
     * Subsequent page of one owner's trail, newest-first, continuing after the {@code (before,
     * beforeId)} cursor (the oldest row of the prior page). {@code before} is always non-null here;
     * because {@code createdAt} is not unique, {@code eventId} breaks ties so pages never skip or
     * repeat rows sharing a timestamp. The first page is split out into {@link #pageFirstEntities}
     * so this query never carries an untyped {@code :before is null} parameter, which PostgreSQL
     * cannot resolve (it has no comparison column to infer the timestamp type from).
     */
    @Query(
            """
            select e
              from AuditEventEntity e
             where e.ownerId = :ownerId
               and (:vaultId is null or e.vaultId = :vaultId)
               and (e.createdAt < :before
                    or (e.createdAt = :before and e.eventId < :beforeId))
             order by e.createdAt desc, e.eventId desc
            """)
    @NonNull List<AuditEventEntity> pageCursorEntities(
            @Param("ownerId") @NonNull String ownerId,
            @Param("vaultId") @Nullable String vaultId,
            @Param("before") @NonNull Instant before,
            @Param("beforeId") @NonNull String beforeId,
            @NonNull Pageable pageable);

    default @NonNull List<AuditEventEntity> pageCursor(
            @NonNull String ownerId,
            @Nullable String vaultId,
            @NonNull Instant before,
            @NonNull String beforeId,
            int limit) {
        return pageCursorEntities(
                ownerId, vaultId, before, beforeId, Pageable.ofSize(Math.max(1, limit)));
    }
}
