package top.focess.keystead.server.vault;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

record StoredVaultMember(
        @NonNull String vaultId,
        @NonNull String userId,
        @NonNull VaultMemberRole role,
        @NonNull VaultMemberState state,
        @NonNull Instant createdAt,
        @NonNull Instant updatedAt) {

    StoredVaultMember {
        requireNotBlank(vaultId, "vaultId");
        requireNotBlank(userId, "userId");
        Objects.requireNonNull(role, "role");
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (updatedAt.isBefore(createdAt)) {
            throw new IllegalArgumentException(
                    "Vault member updated time must not be before created time");
        }
        if (role == VaultMemberRole.OWNER && state != VaultMemberState.ACTIVE) {
            throw new IllegalArgumentException("Vault owner must be active");
        }
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
