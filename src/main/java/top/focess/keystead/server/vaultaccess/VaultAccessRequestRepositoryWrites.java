package top.focess.keystead.server.vaultaccess;

import org.jspecify.annotations.NonNull;

interface VaultAccessRequestRepositoryWrites {
    void insert(@NonNull VaultAccessRequestEntity entity);
}
