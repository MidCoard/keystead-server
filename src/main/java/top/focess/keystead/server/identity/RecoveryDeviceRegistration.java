package top.focess.keystead.server.identity;

import org.jspecify.annotations.NonNull;

public record RecoveryDeviceRegistration(
        @NonNull String deviceId,
        @NonNull String proofKeyAlgorithm,
        @NonNull String proofPublicKey,
        @NonNull String wrappingKeyAlgorithm,
        @NonNull String wrappingPublicKey) {}
