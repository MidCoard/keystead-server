package top.focess.keystead.server.record;

import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
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

    default void insert(@NonNull StoredEncryptedRecord record) {
        save(EncryptedRecordEntity.from(record));
    }

    default void update(@NonNull StoredEncryptedRecord record) {
        save(EncryptedRecordEntity.from(record));
    }
}
