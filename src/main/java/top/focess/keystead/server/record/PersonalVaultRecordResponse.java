package top.focess.keystead.server.record;

import java.time.Instant;
import org.jspecify.annotations.NonNull;

public record PersonalVaultRecordResponse(
        long serverSequence,
        @NonNull String eventId,
        @NonNull String fingerprint,
        @NonNull String secretId,
        long revision,
        @NonNull String secretType,
        @NonNull String encryptedProfile,
        @NonNull String envelope,
        boolean deleted,
        @NonNull Instant createdAt) {

    static @NonNull PersonalVaultRecordResponse from(@NonNull VaultRecordEventEntity entity) {
        return new PersonalVaultRecordResponse(
                entity.serverSequence,
                entity.eventId,
                entity.fingerprint,
                entity.secretId,
                entity.revision,
                entity.secretType,
                entity.encryptedProfile,
                entity.envelope,
                entity.deleted,
                entity.createdAt);
    }
}
