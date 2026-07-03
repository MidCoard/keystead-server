package top.focess.keystead.server.vault;

import java.time.Instant;
import org.jspecify.annotations.NonNull;

record StoredVaultKeyPackage(
        @NonNull String ownerId,
        @NonNull String vaultId,
        @NonNull String deviceId,
        @NonNull String keyAlgorithm,
        @NonNull String encryptedVaultKey,
        @NonNull Instant createdAt,
        @NonNull Instant updatedAt) {}
