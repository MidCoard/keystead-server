package top.focess.keystead.server.vault;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import java.util.Set;
import org.jspecify.annotations.NonNull;

public record VaultRotationBeginRequest(
        @NotBlank @Size(max = 255) @NonNull String expectedCurrentVaultKeyId,
        @NotBlank @Size(max = 255) @NonNull String targetVaultKeyId,
        @Positive long expectedLifecycleVersion,
        @Size(max = 1024)
                @NonNull Set<@NotBlank @Size(max = 255) @NonNull String> selectedPendingUsers) {

    public VaultRotationBeginRequest {
        selectedPendingUsers = Set.copyOf(selectedPendingUsers);
    }
}
