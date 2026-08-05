package top.focess.keystead.server.record;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecretType;

public record PersonalVaultRecordRequest(
        @NotBlank @Size(max = 128) @NonNull String eventId,
        @NotBlank @Size(max = 255) @NonNull String fingerprint,
        @NotBlank @Size(max = 255) @NonNull String secretId,
        @Positive long revision,
        @NotBlank @Size(max = 64) @NonNull String secretType,
        @Size(max = 262144) @NonNull String encryptedProfile,
        @Size(max = 262144) @NonNull String envelope,
        boolean deleted,
        @NotBlank @Size(max = 128) @NonNull String contentKey) {

    void validateShape() {
        try {
            SecretType.valueOf(secretType);
        } catch (IllegalArgumentException error) {
            throw new InvalidPersonalVaultRecordException("Secret type is unsupported");
        }
        if (deleted) {
            if (encryptedProfile.isBlank() || !envelope.isEmpty()) {
                throw new InvalidPersonalVaultRecordException(
                        "Deleted record requires an authenticated control envelope");
            }
        } else if (encryptedProfile.isBlank() || envelope.isBlank()) {
            throw new InvalidPersonalVaultRecordException(
                    "Active record requires encrypted profile and payload envelopes");
        }
    }
}
