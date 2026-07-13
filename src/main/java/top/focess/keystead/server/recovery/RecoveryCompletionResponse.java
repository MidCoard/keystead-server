package top.focess.keystead.server.recovery;

import java.util.List;
import org.jspecify.annotations.NonNull;

public record RecoveryCompletionResponse(
        boolean accountRecovered,
        @NonNull String deviceId,
        @NonNull List<String> recoveredVaultIds,
        @NonNull List<String> pendingVaultIds,
        boolean replacementKitRequired) {

    public RecoveryCompletionResponse {
        recoveredVaultIds = List.copyOf(recoveredVaultIds);
        pendingVaultIds = List.copyOf(pendingVaultIds);
    }
}
