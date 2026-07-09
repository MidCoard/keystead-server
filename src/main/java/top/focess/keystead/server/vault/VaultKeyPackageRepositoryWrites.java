package top.focess.keystead.server.vault;

import org.jspecify.annotations.NonNull;

interface VaultKeyPackageRepositoryWrites {

    void insert(@NonNull StoredVaultKeyPackage keyPackage);

    void update(@NonNull StoredVaultKeyPackage keyPackage);
}
