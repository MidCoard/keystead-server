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
        @Size(max = EncryptedRecordLimits.ENVELOPE_MAX_LENGTH) @Nullable String envelope,
        boolean deleted) {

    @NonNull String resolvedEncryptedProfile() {
        if (deleted) {
            if (hasText(metadata) || hasText(encryptedProfile)) {
                throw new InvalidRecordRequestException(
                        "tombstone must not include encryptedProfile");
            }
            return "";
        }
        if (hasText(encryptedProfile)) {
            return encryptedProfile;
        }
        if (hasText(metadata)) {
            return metadata;
        }
        throw new InvalidRecordRequestException("encryptedProfile is required");
    }

    @NonNull String resolvedEnvelope() {
        if (deleted) {
            if (hasText(envelope)) {
                throw new InvalidRecordRequestException("tombstone must not include envelope");
            }
            return "";
        }
        if (hasText(envelope)) {
            return envelope;
        }
        throw new InvalidRecordRequestException("envelope is required");
    }

    private static boolean hasText(@Nullable String value) {
        return value != null && !value.isBlank();
    }
}
