package top.focess.keystead.server.vault;

import java.time.Instant;
import org.jspecify.annotations.NonNull;

public record VaultKeyPackageResponse(
        @NonNull String vaultId,
        @NonNull String deviceId,
        @NonNull String keyAlgorithm,
        @NonNull String encryptedVaultKey,
        @NonNull Instant createdAt,
        @NonNull Instant updatedAt) {

    static @NonNull VaultKeyPackageResponse from(@NonNull StoredVaultKeyPackage keyPackage) {
        return new VaultKeyPackageResponse(
                keyPackage.vaultId(),
                keyPackage.deviceId(),
                keyPackage.keyAlgorithm(),
                keyPackage.encryptedVaultKey(),
                keyPackage.createdAt(),
                keyPackage.updatedAt());
    }
}
