package top.focess.keystead.server.record;

import java.time.Instant;
import org.jspecify.annotations.NonNull;

public record EncryptedRecordResponse(
        @NonNull String vaultId,
        @NonNull String secretId,
        long revision,
        @NonNull String secretType,
        @NonNull String metadata,
        @NonNull String envelope,
        boolean deleted,
        @NonNull Instant updatedAt) {

    static @NonNull EncryptedRecordResponse from(@NonNull StoredEncryptedRecord record) {
        return new EncryptedRecordResponse(
                record.vaultId(),
                record.secretId(),
                record.revision(),
                record.secretType(),
                record.metadata(),
                record.envelope(),
                record.deleted(),
                record.updatedAt());
    }
}
