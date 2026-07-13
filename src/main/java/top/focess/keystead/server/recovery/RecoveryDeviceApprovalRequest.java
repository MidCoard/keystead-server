package top.focess.keystead.server.recovery;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.List;
import org.jspecify.annotations.NonNull;

public record RecoveryDeviceApprovalRequest(
        @NotBlank @Size(max = 255) @NonNull String deviceId,
        @NotBlank @Size(max = 8192) @NonNull String signature,
        @Size(max = 1024) @NonNull List<@Valid RecoveryApprovalVaultPackage> vaultPackages) {

    public RecoveryDeviceApprovalRequest {
        vaultPackages = List.copyOf(vaultPackages);
    }

    @Override
    public @NonNull String toString() {
        return "RecoveryDeviceApprovalRequest[deviceId=%s, signature=[REDACTED %d chars], vaultPackages=%d]"
                .formatted(deviceId, signature.length(), vaultPackages.size());
    }
}
