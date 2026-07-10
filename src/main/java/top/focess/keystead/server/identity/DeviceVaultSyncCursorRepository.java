package top.focess.keystead.server.identity;

import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;

interface DeviceVaultSyncCursorRepository
        extends JpaRepository<DeviceVaultSyncCursorEntity, DeviceVaultSyncCursorEntityId>,
                DeviceVaultSyncCursorRepositoryWrites {

    default @NonNull Optional<StoredDeviceVaultSyncCursor> find(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String deviceId) {
        return findById(new DeviceVaultSyncCursorEntityId(ownerId, vaultId, deviceId))
                .map(DeviceVaultSyncCursorEntity::toStored);
    }
}
