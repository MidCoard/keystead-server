package top.focess.keystead.server.vault;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public record VaultMembershipResponse(
        @NonNull String vaultId,
        @NonNull String ownerId,
        @NonNull String encryptedMetadata,
        @NonNull VaultMemberRole role,
        @NonNull VaultMemberState membershipState,
        @Nullable String currentVaultKeyId,
        @NonNull VaultKeyLifecycleState keyLifecycleState,
        long lifecycleVersion) {}
