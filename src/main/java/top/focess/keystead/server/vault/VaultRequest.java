package top.focess.keystead.server.vault;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;

public record VaultRequest(
        @NotBlank @Size(max = VaultLimits.ENCRYPTED_METADATA_MAX_LENGTH)
                @NonNull String encryptedMetadata) {}
