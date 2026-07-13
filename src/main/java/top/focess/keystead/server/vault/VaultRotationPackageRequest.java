package top.focess.keystead.server.vault;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public record VaultRotationPackageRequest(
        @NotBlank @Size(max = 255) @NonNull String vaultKeyId,
        @NonNull VaultRotationTargetType targetType,
        @Size(max = 255) @Nullable String recipientId,
        @Size(max = 255) @Nullable String deviceId,
        @Size(max = 255) @Nullable String principalId,
        @Size(max = 255) @Nullable String enrollmentId,
        @Positive @Nullable Long recoveryGeneration,
        @NotBlank @Size(max = 64) @NonNull String keyAlgorithm,
        @NotBlank @Size(max = VaultKeyPackageLimits.ENCRYPTED_VAULT_KEY_MAX_LENGTH)
                @NonNull String encryptedVaultKey) {

    @Override
    public @NonNull String toString() {
        return "VaultRotationPackageRequest[vaultKeyId="
                + vaultKeyId
                + ", targetType="
                + targetType
                + ", recipientId="
                + recipientId
                + ", deviceId="
                + deviceId
                + ", principalId="
                + principalId
                + ", enrollmentId="
                + enrollmentId
                + ", recoveryGeneration="
                + recoveryGeneration
                + ", keyAlgorithm="
                + keyAlgorithm
                + ", encryptedVaultKey=<redacted>]";
    }
}
