package top.focess.keystead.server.recovery;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;

public record RecoveryDeviceClaimRequest(@NotBlank @Size(max = 8192) @NonNull String signature) {

    @Override
    public @NonNull String toString() {
        return "RecoveryDeviceClaimRequest[signature=[REDACTED %d chars]]"
                .formatted(signature.length());
    }
}
