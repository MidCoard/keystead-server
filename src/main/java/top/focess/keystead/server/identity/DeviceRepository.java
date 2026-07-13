package top.focess.keystead.server.identity;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface DeviceRepository
        extends JpaRepository<DeviceEntity, DeviceEntityId>, DeviceRepositoryWrites {

    @Query("select d from DeviceEntity d where d.id.ownerId = :ownerId order by d.id.deviceId")
    @NonNull List<DeviceEntity> listEntities(@Param("ownerId") @NonNull String ownerId);

    default @NonNull List<StoredDevice> list(@NonNull String ownerId) {
        return listEntities(ownerId).stream().map(DeviceEntity::toStored).toList();
    }

    default @NonNull Optional<StoredDevice> find(
            @NonNull String ownerId, @NonNull String deviceId) {
        return findById(new DeviceEntityId(ownerId, deviceId)).map(DeviceEntity::toStored);
    }

    @Modifying
    @Query(
            """
            update DeviceEntity d
               set d.verifiedAt = :when, d.lastSeenAt = :when
             where d.id.ownerId = :ownerId
               and d.id.deviceId = :deviceId
               and d.revokedAt is null
            """)
    int markVerifiedActive(
            @Param("ownerId") @NonNull String ownerId,
            @Param("deviceId") @NonNull String deviceId,
            @Param("when") @NonNull Instant when);

    @Modifying
    @Query(
            """
            update DeviceEntity d
               set d.revokedAt = :when
             where d.id.ownerId = :ownerId
               and d.id.deviceId = :deviceId
               and d.revokedAt is null
            """)
    int revokeActive(
            @Param("ownerId") @NonNull String ownerId,
            @Param("deviceId") @NonNull String deviceId,
            @Param("when") @NonNull Instant when);
}
