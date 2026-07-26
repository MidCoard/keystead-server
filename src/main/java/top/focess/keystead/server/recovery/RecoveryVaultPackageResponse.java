package top.focess.keystead.server.recovery;

import java.time.Instant;
import org.jspecify.annotations.NonNull;

public record RecoveryVaultPackageResponse(
        @NonNull String enrollmentId,
        long generation,
        @NonNull String fingerprint,
        @NonNull String vaultKeyId,
        @NonNull String keyAlgorithm,
        @NonNull String encryptedVaultKey,
        @NonNull Instant updatedAt) {

    static @NonNull RecoveryVaultPackageResponse from(@NonNull RecoveryVaultPackageEntity entity) {
        return new RecoveryVaultPackageResponse(
                entity.id.enrollmentId,
                entity.id.generation,
                entity.id.fingerprint,
                entity.vaultKeyId,
                entity.keyAlgorithm,
                entity.encryptedVaultKey,
                entity.updatedAt);
    }

    @Override
    public @NonNull String toString() {
        return "RecoveryVaultPackageResponse[enrollmentId=%s, generation=%d, fingerprint=%s, vaultKeyId=%s, keyAlgorithm=%s, encryptedVaultKey=[REDACTED %d chars], updatedAt=%s]"
                .formatted(
                        enrollmentId,
                        generation,
                        fingerprint,
                        vaultKeyId,
                        keyAlgorithm,
                        encryptedVaultKey.length(),
                        updatedAt);
    }
}
