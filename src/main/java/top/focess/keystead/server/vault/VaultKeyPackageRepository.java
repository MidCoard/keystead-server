package top.focess.keystead.server.vault;

import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface VaultKeyPackageRepository
        extends JpaRepository<VaultKeyPackageEntity, VaultKeyPackageEntityId> {

    default @NonNull Optional<StoredVaultKeyPackage> find(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String deviceId) {
        return findById(new VaultKeyPackageEntityId(ownerId, vaultId, deviceId))
                .map(VaultKeyPackageEntity::toStored);
    }

    @Query(
            """
            select count(d)
              from DeviceEntity d
             where d.id.ownerId = :ownerId
               and d.id.deviceId = :deviceId
               and d.verifiedAt is not null
               and d.revokedAt is null
            """)
    long countVerifiedDevice(
            @Param("ownerId") @NonNull String ownerId, @Param("deviceId") @NonNull String deviceId);

    default boolean verifiedDeviceExists(@NonNull String ownerId, @NonNull String deviceId) {
        return countVerifiedDevice(ownerId, deviceId) > 0;
    }

    @Query(
            """
            select k
              from VaultKeyPackageEntity k
              join DeviceEntity d
                on d.id.ownerId = k.id.ownerId
               and d.id.deviceId = k.id.deviceId
             where k.id.ownerId = :ownerId and k.id.vaultId = :vaultId
               and d.verifiedAt is not null
               and d.revokedAt is null
             order by k.id.deviceId
            """)
    @NonNull List<VaultKeyPackageEntity> listEntities(
            @Param("ownerId") @NonNull String ownerId, @Param("vaultId") @NonNull String vaultId);

    default @NonNull List<StoredVaultKeyPackage> list(
            @NonNull String ownerId, @NonNull String vaultId) {
        return listEntities(ownerId, vaultId).stream()
                .map(VaultKeyPackageEntity::toStored)
                .toList();
    }

    default void upsert(@NonNull StoredVaultKeyPackage keyPackage) {
        save(VaultKeyPackageEntity.from(keyPackage));
    }
}
