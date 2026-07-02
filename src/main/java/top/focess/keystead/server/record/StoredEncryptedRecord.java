package top.focess.keystead.server.record;

import java.time.Instant;
import org.jspecify.annotations.NonNull;

record StoredEncryptedRecord(
        @NonNull String ownerId,
        @NonNull String vaultId,
        @NonNull String secretId,
        long revision,
        @NonNull String secretType,
        @NonNull String metadata,
        @NonNull String envelope,
        boolean deleted,
        @NonNull Instant updatedAt) {}
