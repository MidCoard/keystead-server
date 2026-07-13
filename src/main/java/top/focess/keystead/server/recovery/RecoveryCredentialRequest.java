package top.focess.keystead.server.recovery;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;

public record RecoveryCredentialRequest(
        @NotBlank @Size(max = 255) @NonNull String challengeId,
        @NotBlank @Size(max = RecoveryLimits.CREDENTIAL_MAX_LENGTH)
                @NonNull String accountCredential) {

    @Override
    public @NonNull String toString() {
        return "RecoveryCredentialRequest[challengeId=%s, accountCredential=[REDACTED]]"
                .formatted(challengeId);
    }
}
