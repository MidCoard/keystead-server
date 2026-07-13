package top.focess.keystead.server.vault;

import org.jspecify.annotations.NonNull;

public record VaultRotationPackageResponse(
        @NonNull String targetId,
        @NonNull String vaultKeyId,
        @NonNull String keyAlgorithm,
        @NonNull String encryptedVaultKey) {

    @Override
    public @NonNull String toString() {
        return "VaultRotationPackageResponse[targetId="
                + targetId
                + ", vaultKeyId="
                + vaultKeyId
                + ", keyAlgorithm="
                + keyAlgorithm
                + ", encryptedVaultKey=<redacted>]";
    }
}
