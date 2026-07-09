package top.focess.keystead.server.vault;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.server.crypto.ServerCryptoAlgorithmRegistry;

public record VaultKeyPackageRequest(
        @NotBlank @Size(max = 64) @NonNull String keyAlgorithm,
        @NotBlank @Size(max = VaultKeyPackageLimits.ENCRYPTED_VAULT_KEY_MAX_LENGTH)
                @NonNull String encryptedVaultKey) {

    void validateShape() {
        if (keyAlgorithm.isBlank()) {
            throw new InvalidVaultKeyPackageRequestException("keyAlgorithm is required");
        }
        if (!ServerCryptoAlgorithmRegistry.isApprovedVaultKeyPackageAlgorithm(keyAlgorithm)) {
            throw new InvalidVaultKeyPackageRequestException(
                    "Unsupported vault key package algorithm");
        }
        if (encryptedVaultKey.isBlank()) {
            throw new InvalidVaultKeyPackageRequestException("encryptedVaultKey is required");
        }
    }
}
