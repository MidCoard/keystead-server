package top.focess.keystead.server.record;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record EncryptedRecordResponse(
        @NonNull String vaultId,
        @NonNull String secretId,
        long revision,
        @NonNull String secretType,
        @Nullable String metadata,
        @Nullable String encryptedProfile,
        @Nullable String envelope,
        boolean deleted,
        @NonNull Instant updatedAt) {

    static @NonNull EncryptedRecordResponse from(@NonNull StoredEncryptedRecord record) {
        boolean deleted = record.deleted();
        return new EncryptedRecordResponse(
                record.vaultId(),
                record.secretId(),
                record.revision(),
                record.secretType(),
                null,
                deleted ? null : record.encryptedProfile(),
                deleted ? null : record.envelope(),
                deleted,
                record.updatedAt());
    }
}
