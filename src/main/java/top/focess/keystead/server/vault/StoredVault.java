package top.focess.keystead.server.vault;

import java.time.Instant;
import org.jspecify.annotations.NonNull;

record StoredVault(
        @NonNull String ownerId,
        @NonNull String vaultId,
        @NonNull String encryptedMetadata,
        @NonNull Instant createdAt,
        @NonNull Instant updatedAt) {}
