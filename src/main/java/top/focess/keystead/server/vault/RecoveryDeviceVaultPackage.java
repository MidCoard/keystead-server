package top.focess.keystead.server.vault;

import org.jspecify.annotations.NonNull;

public record RecoveryDeviceVaultPackage(
        @NonNull String vaultId,
        @NonNull String vaultKeyId,
        @NonNull String keyAlgorithm,
        @NonNull String encryptedVaultKey) {

    @Override
    public @NonNull String toString() {
        return "RecoveryDeviceVaultPackage[vaultId=%s, vaultKeyId=%s, keyAlgorithm=%s, encryptedVaultKey=[REDACTED %d chars]]"
                .formatted(vaultId, vaultKeyId, keyAlgorithm, encryptedVaultKey.length());
    }
}
