package top.focess.keystead.server.record;

import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface VaultRecordEventRepository extends JpaRepository<VaultRecordEventEntity, Long> {

    @NonNull Optional<VaultRecordEventEntity> findByOwnerIdAndEventId(
            @NonNull String ownerId, @NonNull String eventId);

    @NonNull Optional<VaultRecordEventEntity>
            findFirstByOwnerIdAndSecretIdOrderByServerSequenceDesc(
                    @NonNull String ownerId, @NonNull String secretId);

    long deleteByOwnerIdAndSecretId(@NonNull String ownerId, @NonNull String secretId);

    boolean existsByOwnerId(@NonNull String ownerId);

    @Query(
            """
            select e from VaultRecordEventEntity e
             where e.ownerId = :ownerId
               and e.serverSequence > :afterSequence
             order by e.serverSequence asc
            """)
    @NonNull List<VaultRecordEventEntity> pageAfter(
            @Param("ownerId") @NonNull String ownerId,
            @Param("afterSequence") long afterSequence,
            @NonNull Pageable pageable);
}
