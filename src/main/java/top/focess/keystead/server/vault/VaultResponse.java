package top.focess.keystead.server.vault;

import java.time.Instant;
import org.jspecify.annotations.NonNull;

public record VaultResponse(
        @NonNull String vaultId,
        @NonNull String encryptedMetadata,
        @NonNull Instant createdAt,
        @NonNull Instant updatedAt) {

    static @NonNull VaultResponse from(@NonNull StoredVault vault) {
        return new VaultResponse(
                vault.vaultId(), vault.encryptedMetadata(), vault.createdAt(), vault.updatedAt());
    }
}
