package top.focess.keystead.server.record;

import org.jspecify.annotations.NonNull;

record PersonalVaultRecordDeletionResponse(@NonNull String secretId, long deletedEvents) {

    PersonalVaultRecordDeletionResponse {
        if (secretId.isBlank()) {
            throw new IllegalArgumentException("Secret id must not be blank");
        }
        if (deletedEvents < 0) {
            throw new IllegalArgumentException("Deleted event count must not be negative");
        }
    }
}
