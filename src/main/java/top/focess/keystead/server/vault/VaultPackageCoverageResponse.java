package top.focess.keystead.server.vault;

import java.util.List;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public record VaultPackageCoverageResponse(
        @Nullable String currentVaultKeyId,
        @NonNull VaultKeyLifecycleState keyLifecycleState,
        long lifecycleVersion,
        @NonNull List<@NonNull VaultPackageRecipientDeviceResponse> devices) {

    public VaultPackageCoverageResponse {
        devices = List.copyOf(devices);
    }
}
