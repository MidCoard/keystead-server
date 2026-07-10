package top.focess.keystead.server.vault;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;

record VaultKeyRotationRequest(@NotBlank @Size(max = 255) @NonNull String vaultKeyId) {}
