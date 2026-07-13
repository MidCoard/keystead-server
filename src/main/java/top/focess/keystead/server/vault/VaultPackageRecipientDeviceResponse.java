package top.focess.keystead.server.vault;

import org.jspecify.annotations.NonNull;

public record VaultPackageRecipientDeviceResponse(
        @NonNull String userId,
        @NonNull VaultMemberRole role,
        @NonNull VaultMemberState memberState,
        @NonNull String deviceId,
        @NonNull String keyAlgorithm,
        @NonNull String publicKey,
        boolean covered) {}
