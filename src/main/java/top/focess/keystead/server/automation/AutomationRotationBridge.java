package top.focess.keystead.server.automation;

import java.time.Instant;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AutomationRotationBridge {

    private final AutomationPrincipalRepository principals;
    private final AutomationVaultKeyPackageRepository packages;

    AutomationRotationBridge(
            @NonNull AutomationPrincipalRepository principals,
            @NonNull AutomationVaultKeyPackageRepository packages) {
        this.principals = principals;
        this.packages = packages;
    }

    @Transactional(readOnly = true)
    public @NonNull List<Target> targets(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String currentVaultKeyId) {
        return principals.listRotationTargets(ownerId, vaultId, currentVaultKeyId).stream()
                .map(
                        value ->
                                new Target(
                                        value.id.principalId,
                                        value.publicKeyAlgorithm,
                                        value.publicKey))
                .toList();
    }

    @Transactional
    public void replace(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull String targetVaultKeyId,
            @NonNull List<Package> replacements,
            @NonNull Instant now) {
        packages.deleteForVault(ownerId, vaultId);
        for (Package replacement : replacements) {
            packages.persist(
                    new AutomationVaultKeyPackage(
                            ownerId,
                            vaultId,
                            replacement.principalId(),
                            targetVaultKeyId,
                            replacement.keyAlgorithm(),
                            replacement.encryptedVaultKey(),
                            now,
                            now));
        }
    }

    public record Target(
            @NonNull String principalId, @NonNull String keyAlgorithm, @NonNull String publicKey) {}

    public record Package(
            @NonNull String principalId,
            @NonNull String keyAlgorithm,
            @NonNull String encryptedVaultKey) {

        @Override
        public @NonNull String toString() {
            return "Package[principalId=%s, keyAlgorithm=%s, encryptedVaultKey=[REDACTED %d chars]]"
                    .formatted(principalId, keyAlgorithm, encryptedVaultKey.length());
        }
    }
}
