package top.focess.keystead.server.identity;

import org.jspecify.annotations.NonNull;

interface DeviceRepositoryWrites {

    void insert(@NonNull StoredDevice device);

    void update(@NonNull StoredDevice device);
}
