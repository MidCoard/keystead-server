package top.focess.keystead.server.vaultaccess;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;

public record VaultAccessApprovalRequest(
        @NotBlank @Size(max = 255) @NonNull String vaultFingerprint,
        @NotBlank @Size(max = 255) @NonNull String vaultKeyId,
        @NotBlank @Size(max = 64) @NonNull String keyAlgorithm,
        @NotBlank @Size(max = 2 * 1024 * 1024) @NonNull String encryptedVaultKey) {

    @Override
    public @NonNull String toString() {
        return "VaultAccessApprovalRequest[vaultFingerprint=%s, vaultKeyId=%s, keyAlgorithm=%s, encryptedVaultKey=[REDACTED %d chars]]"
                .formatted(vaultFingerprint, vaultKeyId, keyAlgorithm, encryptedVaultKey.length());
    }
}
