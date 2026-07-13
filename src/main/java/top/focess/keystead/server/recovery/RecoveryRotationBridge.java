package top.focess.keystead.server.recovery;

import java.time.Instant;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RecoveryRotationBridge {

    private final RecoveryEnrollmentRepository enrollments;
    private final RecoveryVaultPackageRepository packages;

    RecoveryRotationBridge(
            @NonNull RecoveryEnrollmentRepository enrollments,
            @NonNull RecoveryVaultPackageRepository packages) {
        this.enrollments = enrollments;
        this.packages = packages;
    }

    @Transactional(readOnly = true)
    public @NonNull List<Target> targets(
            @NonNull String username, @NonNull String vaultId, @NonNull String currentVaultKeyId) {
        return enrollments.listRotationTargets(username, vaultId, currentVaultKeyId).stream()
                .map(
                        value ->
                                new Target(
                                        value.id.enrollmentId,
                                        value.id.generation,
                                        value.wrappingAlgorithm,
                                        value.wrappingPublicKey))
                .toList();
    }

    @Transactional
    public void replace(
            @NonNull String username,
            @NonNull String vaultId,
            @NonNull String targetVaultKeyId,
            @NonNull List<Package> replacements,
            @NonNull Instant now) {
        packages.deleteForVault(username, vaultId);
        for (Package replacement : replacements) {
            RecoveryVaultPackageEntity entity = new RecoveryVaultPackageEntity();
            entity.id =
                    new RecoveryVaultPackageId(
                            username,
                            replacement.enrollmentId(),
                            replacement.generation(),
                            vaultId);
            entity.vaultKeyId = targetVaultKeyId;
            entity.keyAlgorithm = replacement.keyAlgorithm();
            entity.encryptedVaultKey = replacement.encryptedVaultKey();
            entity.createdAt = now;
            entity.updatedAt = now;
            packages.save(entity);
        }
        packages.flush();
    }

    public record Target(
            @NonNull String enrollmentId,
            long generation,
            @NonNull String keyAlgorithm,
            @NonNull String publicKey) {}

    public record Package(
            @NonNull String enrollmentId,
            long generation,
            @NonNull String keyAlgorithm,
            @NonNull String encryptedVaultKey) {

        @Override
        public @NonNull String toString() {
            return "Package[enrollmentId=%s, generation=%d, keyAlgorithm=%s, encryptedVaultKey=[REDACTED %d chars]]"
                    .formatted(enrollmentId, generation, keyAlgorithm, encryptedVaultKey.length());
        }
    }
}
