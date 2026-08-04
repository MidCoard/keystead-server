package top.focess.keystead.server.vaultaccess;

import org.jspecify.annotations.NonNull;

public record VaultAccessApprovedPackageResponse(
        @NonNull String vaultFingerprint,
        @NonNull String vaultKeyId,
        @NonNull String keyAlgorithm,
        @NonNull String encryptedVaultKey) {

    @Override
    public @NonNull String toString() {
        return "VaultAccessApprovedPackageResponse[vaultFingerprint=%s, vaultKeyId=%s, keyAlgorithm=%s, encryptedVaultKey=[REDACTED %d chars]]"
                .formatted(vaultFingerprint, vaultKeyId, keyAlgorithm, encryptedVaultKey.length());
    }
}
