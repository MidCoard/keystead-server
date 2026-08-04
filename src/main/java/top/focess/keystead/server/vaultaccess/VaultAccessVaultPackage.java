package top.focess.keystead.server.vaultaccess;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;

public record VaultAccessVaultPackage(
        @NotBlank @Size(max = 255) @NonNull String fingerprint,
        @NotBlank @Size(max = 255) @NonNull String vaultKeyId,
        @NotBlank @Size(max = 64) @NonNull String keyAlgorithm,
        @NotBlank @Size(max = 1_048_576) @NonNull String encryptedVaultKey) {

    @Override
    public @NonNull String toString() {
        return "VaultAccessVaultPackage[fingerprint=%s, vaultKeyId=%s, keyAlgorithm=%s, encryptedVaultKey=[REDACTED %d chars]]"
                .formatted(fingerprint, vaultKeyId, keyAlgorithm, encryptedVaultKey.length());
    }
}
