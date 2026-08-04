package top.focess.keystead.server.vaultaccess;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;

public record VaultAccessCreateRequest(
        @NotBlank @Size(max = 36) @NonNull String requestId,
        @NotBlank @Size(max = 2048) @NonNull String serverOrigin,
        @NotBlank @Size(max = 64) @NonNull String keyAlgorithm,
        @NotBlank @Size(max = 131072) @NonNull String exchangePublicKey) {}
