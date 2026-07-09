package top.focess.keystead.server.record;

import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface EncryptedRecordRepository
        extends JpaRepository<EncryptedRecordEntity, EncryptedRecordEntityId> {

    default @NonNull Optional<StoredEncryptedRecord> find(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String secretId) {
        return findById(new EncryptedRecordEntityId(ownerId, vaultId, secretId))
                .map(EncryptedRecordEntity::toStored);
    }

    @Query(
            """
            select r
              from EncryptedRecordEntity r
             where r.id.ownerId = :ownerId
               and r.id.vaultId = :vaultId
             order by r.revision desc, r.id.secretId desc
            """)
    @NonNull List<EncryptedRecordEntity> latestRevisionEntities(
            @Param("ownerId") @NonNull String ownerId,
            @Param("vaultId") @NonNull String vaultId,
            @NonNull Pageable pageable);

    default @NonNull Optional<StoredEncryptedRecord> latestRevision(
            @NonNull String ownerId, @NonNull String vaultId) {
        return latestRevisionEntities(ownerId, vaultId, Pageable.ofSize(1)).stream()
                .findFirst()
                .map(EncryptedRecordEntity::toStored);
    }

    @Query(
            """
            select r
              from EncryptedRecordEntity r
             where r.id.ownerId = :ownerId
               and r.id.vaultId = :vaultId
               and r.revision > :sinceRevision
             order by r.revision, r.id.secretId
            """)
    @NonNull List<EncryptedRecordEntity> listSinceEntities(
            @Param("ownerId") @NonNull String ownerId,
            @Param("vaultId") @NonNull String vaultId,
            @Param("sinceRevision") long sinceRevision);

    default @NonNull List<StoredEncryptedRecord> listSince(
            @NonNull String ownerId, @NonNull String vaultId, long sinceRevision) {
        return listSinceEntities(ownerId, vaultId, sinceRevision).stream()
                .map(EncryptedRecordEntity::toStored)
                .toList();
    }

    @Query(
            """
            select r
              from EncryptedRecordEntity r
             where r.id.ownerId = :ownerId
               and r.id.vaultId = :vaultId
               and r.revision > :sinceRevision
             order by r.revision, r.id.secretId
            """)
    @NonNull List<EncryptedRecordEntity> pageSinceEntities(
            @Param("ownerId") @NonNull String ownerId,
            @Param("vaultId") @NonNull String vaultId,
            @Param("sinceRevision") long sinceRevision,
            @NonNull Pageable pageable);

    default @NonNull List<StoredEncryptedRecord> pageSince(
            @NonNull String ownerId, @NonNull String vaultId, long sinceRevision, int limit) {
        return pageSinceEntities(
                        ownerId, vaultId, sinceRevision, Pageable.ofSize(Math.max(1, limit)))
                .stream()
                .map(EncryptedRecordEntity::toStored)
                .toList();
    }

    default void insert(@NonNull StoredEncryptedRecord record) {
        saveAndFlush(EncryptedRecordEntity.from(record));
    }

    default void update(@NonNull StoredEncryptedRecord record) {
        saveAndFlush(EncryptedRecordEntity.from(record));
    }
}
