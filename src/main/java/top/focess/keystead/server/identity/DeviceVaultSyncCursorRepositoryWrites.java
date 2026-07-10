package top.focess.keystead.server.identity;

import org.jspecify.annotations.NonNull;

interface DeviceVaultSyncCursorRepositoryWrites {

    void insert(@NonNull StoredDeviceVaultSyncCursor cursor);

    void update(@NonNull StoredDeviceVaultSyncCursor cursor);
}
