package top.focess.keystead.server.record;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public record EncryptedRecordRequest(
        @Positive long revision,
        @NotBlank @NonNull String secretType,
        @Size(max = EncryptedRecordLimits.ENCRYPTED_PROFILE_MAX_LENGTH) @Nullable String metadata,
        @Size(max = EncryptedRecordLimits.ENCRYPTED_PROFILE_MAX_LENGTH)
                @Nullable String encryptedProfile,
        @NotBlank @Size(max = EncryptedRecordLimits.ENVELOPE_MAX_LENGTH) @NonNull String envelope,
        boolean deleted) {

    @NonNull String resolvedEncryptedProfile() {
        if (encryptedProfile != null && !encryptedProfile.isBlank()) {
            return encryptedProfile;
        }
        if (metadata != null && !metadata.isBlank()) {
            return metadata;
        }
        throw new InvalidRecordRequestException("encryptedProfile is required");
    }
}
