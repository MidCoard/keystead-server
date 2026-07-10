package top.focess.keystead.server.automation;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.server.crypto.ServerCryptoAlgorithmRegistry;

record AutomationVaultKeyPackageRequest(
        @NotBlank @Size(max = 255) @NonNull String vaultKeyId,
        @NotBlank @Size(max = 64) @NonNull String keyAlgorithm,
        @NotBlank @Size(max = 1_048_576) @NonNull String encryptedVaultKey) {

    void validateShape() {
        if (!ServerCryptoAlgorithmRegistry.isApprovedVaultKeyPackageAlgorithm(keyAlgorithm)) {
            throw new InvalidAutomationRequestException(
                    "Vault key package algorithm is unsupported");
        }
    }
}
