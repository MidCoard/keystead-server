package top.focess.keystead.server.recovery;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.List;
import org.jspecify.annotations.NonNull;

public record RecoveryCompletionRequest(
        @NotBlank @Size(min = 12, max = 1024) @NonNull String newPassword,
        @NotBlank @Size(max = 255) @NonNull String deviceId,
        @NotBlank @Size(max = 64) @NonNull String proofKeyAlgorithm,
        @NotBlank @Size(max = RecoveryLimits.PUBLIC_KEY_MAX_LENGTH) @NonNull String proofPublicKey,
        @NotBlank @Size(max = 64) @NonNull String wrappingKeyAlgorithm,
        @NotBlank @Size(max = RecoveryLimits.PUBLIC_KEY_MAX_LENGTH)
                @NonNull String wrappingPublicKey,
        @Size(max = 4096) @NonNull List<@Valid RecoveryCompletionVaultPackage> vaultPackages) {

    public RecoveryCompletionRequest {
        vaultPackages = List.copyOf(vaultPackages);
    }

    @Override
    public @NonNull String toString() {
        return "RecoveryCompletionRequest[newPassword=[REDACTED %d chars], deviceId=%s, proofKeyAlgorithm=%s, proofPublicKey=[PUBLIC %d chars], wrappingKeyAlgorithm=%s, wrappingPublicKey=[PUBLIC %d chars], vaultPackages=%d]"
                .formatted(
                        newPassword.length(),
                        deviceId,
                        proofKeyAlgorithm,
                        proofPublicKey.length(),
                        wrappingKeyAlgorithm,
                        wrappingPublicKey.length(),
                        vaultPackages.size());
    }
}
