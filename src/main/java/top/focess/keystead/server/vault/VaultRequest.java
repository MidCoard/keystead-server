package top.focess.keystead.server.vault;

import jakarta.validation.constraints.NotBlank;
import org.jspecify.annotations.NonNull;

public record VaultRequest(@NotBlank @NonNull String encryptedMetadata) {}
