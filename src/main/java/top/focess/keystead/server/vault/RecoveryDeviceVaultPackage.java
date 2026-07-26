package top.focess.keystead.server.vault;

import org.jspecify.annotations.NonNull;

public record RecoveryDeviceVaultPackage(
        @NonNull String fingerprint,
        @NonNull String vaultKeyId,
        @NonNull String keyAlgorithm,
        @NonNull String encryptedVaultKey) {

    @Override
    public @NonNull String toString() {
        return "RecoveryDeviceVaultPackage[fingerprint=%s, vaultKeyId=%s, keyAlgorithm=%s, encryptedVaultKey=[REDACTED %d chars]]"
                .formatted(fingerprint, vaultKeyId, keyAlgorithm, encryptedVaultKey.length());
    }
}
