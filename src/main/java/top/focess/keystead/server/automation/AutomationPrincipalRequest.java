package top.focess.keystead.server.automation;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.server.crypto.ServerCryptoAlgorithmRegistry;

record AutomationPrincipalRequest(
        @NotBlank @Size(max = 64) @NonNull String publicKeyAlgorithm,
        @NotBlank @Size(max = 32_768) @NonNull String publicKey) {

    void validateShape() {
        if (!ServerCryptoAlgorithmRegistry.isApprovedVaultKeyPackageAlgorithm(publicKeyAlgorithm)) {
            throw new InvalidAutomationRequestException("Public key algorithm is unsupported");
        }
    }
}
