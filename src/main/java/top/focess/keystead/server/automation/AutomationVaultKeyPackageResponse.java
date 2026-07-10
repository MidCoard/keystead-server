package top.focess.keystead.server.automation;

import java.time.Instant;
import org.jspecify.annotations.NonNull;

record AutomationVaultKeyPackageResponse(
        @NonNull String vaultId,
        @NonNull String principalId,
        @NonNull String vaultKeyId,
        @NonNull String keyAlgorithm,
        @NonNull String encryptedVaultKey,
        @NonNull Instant createdAt,
        @NonNull Instant updatedAt) {

    static @NonNull AutomationVaultKeyPackageResponse from(
            @NonNull AutomationVaultKeyPackage keyPackage) {
        return new AutomationVaultKeyPackageResponse(
                keyPackage.vaultId(),
                keyPackage.principalId(),
                keyPackage.vaultKeyId(),
                keyPackage.keyAlgorithm(),
                keyPackage.encryptedVaultKey(),
                keyPackage.createdAt(),
                keyPackage.updatedAt());
    }
}
