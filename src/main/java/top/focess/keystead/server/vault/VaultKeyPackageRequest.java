package top.focess.keystead.server.vault;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.server.crypto.ServerCryptoAlgorithmRegistry;

public record VaultKeyPackageRequest(
        @Size(max = 255) @Nullable String vaultKeyId,
        @NotBlank @Size(max = 64) @NonNull String keyAlgorithm,
        @NotBlank @Size(max = VaultKeyPackageLimits.ENCRYPTED_VAULT_KEY_MAX_LENGTH)
                @NonNull String encryptedVaultKey) {

    VaultKeyPackageRequest(@NonNull String keyAlgorithm, @NonNull String encryptedVaultKey) {
        this(null, keyAlgorithm, encryptedVaultKey);
    }

    void validateShape() {
        if (vaultKeyId != null && vaultKeyId.isBlank()) {
            throw new InvalidVaultKeyPackageRequestException("vaultKeyId is required");
        }
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

    @NonNull String resolvedVaultKeyId() {
        return vaultKeyId == null ? "legacy" : vaultKeyId;
    }
}
