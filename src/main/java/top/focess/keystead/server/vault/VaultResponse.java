package top.focess.keystead.server.vault;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

public record VaultResponse(
        @NonNull String vaultId,
        @NonNull String encryptedMetadata,
        @NonNull Instant createdAt,
        @NonNull Instant updatedAt) {

    public VaultResponse {
        requireNotBlank(vaultId, "vaultId");
        requireNotBlank(encryptedMetadata, "encryptedMetadata");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (updatedAt.isBefore(createdAt)) {
            throw new IllegalArgumentException(
                    "Vault updated time must not be before created time");
        }
    }

    static @NonNull VaultResponse from(@NonNull StoredVault vault) {
        return new VaultResponse(
                vault.vaultId(), vault.encryptedMetadata(), vault.createdAt(), vault.updatedAt());
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
