package top.focess.keystead.server.recovery;

import java.util.List;
import org.jspecify.annotations.NonNull;

public record RecoveryCompletionResponse(
        boolean accountRecovered,
        @NonNull String deviceId,
        @NonNull List<String> recoveredFingerprints,
        @NonNull List<String> pendingFingerprints,
        boolean replacementKitRequired) {

    public RecoveryCompletionResponse {
        recoveredFingerprints = List.copyOf(recoveredFingerprints);
        pendingFingerprints = List.copyOf(pendingFingerprints);
    }
}
