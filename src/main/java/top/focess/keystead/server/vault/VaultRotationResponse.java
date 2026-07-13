package top.focess.keystead.server.vault;

import java.util.List;
import org.jspecify.annotations.NonNull;

public record VaultRotationResponse(
        @NonNull String generationId,
        @NonNull String vaultId,
        @NonNull String sourceVaultKeyId,
        @NonNull String targetVaultKeyId,
        @NonNull VaultRotationGenerationState state,
        long lifecycleVersion,
        @NonNull List<@NonNull VaultRotationTargetResponse> targets) {

    public VaultRotationResponse {
        targets = List.copyOf(targets);
    }
}
