package top.focess.keystead.server.vault;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public record VaultRotationTargetResponse(
        @NonNull String targetId,
        @NonNull VaultRotationTargetType targetType,
        @Nullable String recipientId,
        @Nullable String deviceId,
        @Nullable String principalId,
        @Nullable String enrollmentId,
        @Nullable Long recoveryGeneration,
        @NonNull String keyAlgorithm,
        @NonNull String publicKey,
        boolean required,
        boolean covered) {}
