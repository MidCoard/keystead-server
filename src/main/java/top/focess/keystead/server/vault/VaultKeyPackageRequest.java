package top.focess.keystead.server.vault;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;

public record VaultKeyPackageRequest(
        @NotBlank @Size(max = 64) @NonNull String keyAlgorithm,
        @NotBlank @Size(max = VaultKeyPackageLimits.ENCRYPTED_VAULT_KEY_MAX_LENGTH)
                @NonNull String encryptedVaultKey) {}
