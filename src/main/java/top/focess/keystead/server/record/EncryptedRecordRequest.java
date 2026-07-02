package top.focess.keystead.server.record;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import org.jspecify.annotations.NonNull;

public record EncryptedRecordRequest(
        @Positive long revision,
        @NotBlank @NonNull String secretType,
        @NotBlank @NonNull String metadata,
        @NotBlank @NonNull String envelope,
        boolean deleted) {}
