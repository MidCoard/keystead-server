package top.focess.keystead.server.recovery;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public record RecoveryEnrollmentRequest(
        @Positive long generation,
        @NotBlank @Size(max = RecoveryLimits.CREDENTIAL_MAX_LENGTH)
                @NonNull String accountCredential,
        @NotBlank @Size(max = 64) @NonNull String wrappingAlgorithm,
        @NotBlank @Size(max = RecoveryLimits.PUBLIC_KEY_MAX_LENGTH)
                @NonNull String wrappingPublicKey,
        @NotBlank @Size(max = RecoveryLimits.CIPHERTEXT_MAX_LENGTH)
                @NonNull String encryptedPrivateKey,
        @Size(max = 128) @Nullable String enrollmentId) {

    public RecoveryEnrollmentRequest(
            long generation,
            @NonNull String accountCredential,
            @NonNull String wrappingAlgorithm,
            @NonNull String wrappingPublicKey,
            @NonNull String encryptedPrivateKey) {
        this(
                generation,
                accountCredential,
                wrappingAlgorithm,
                wrappingPublicKey,
                encryptedPrivateKey,
                null);
    }

    @Override
    public @NonNull String toString() {
        return "RecoveryEnrollmentRequest[generation=%d, accountCredential=[REDACTED], wrappingAlgorithm=%s, wrappingPublicKey=[PUBLIC %d chars], encryptedPrivateKey=[REDACTED %d chars], enrollmentId=%s]"
                .formatted(
                        generation,
                        wrappingAlgorithm,
                        wrappingPublicKey.length(),
                        encryptedPrivateKey.length(),
                        enrollmentId);
    }
}
