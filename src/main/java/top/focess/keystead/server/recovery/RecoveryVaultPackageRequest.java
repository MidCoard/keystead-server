package top.focess.keystead.server.recovery;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;

public record RecoveryVaultPackageRequest(
        @Positive long generation,
        @NotBlank @Size(max = 255) @NonNull String vaultKeyId,
        @NotBlank @Size(max = 64) @NonNull String keyAlgorithm,
        @NotBlank @Size(max = RecoveryLimits.CIPHERTEXT_MAX_LENGTH)
                @NonNull String encryptedVaultKey) {

    @Override
    public @NonNull String toString() {
        return "RecoveryVaultPackageRequest[generation=%d, vaultKeyId=%s, keyAlgorithm=%s, encryptedVaultKey=[REDACTED %d chars]]"
                .formatted(generation, vaultKeyId, keyAlgorithm, encryptedVaultKey.length());
    }
}
