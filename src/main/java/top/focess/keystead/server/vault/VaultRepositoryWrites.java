package top.focess.keystead.server.vault;

import org.jspecify.annotations.NonNull;

interface VaultRepositoryWrites {

    void insert(@NonNull StoredVault vault);

    void update(@NonNull StoredVault vault);
}
