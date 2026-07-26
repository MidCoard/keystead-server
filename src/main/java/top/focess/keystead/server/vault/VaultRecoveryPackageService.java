package top.focess.keystead.server.vault;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.server.audit.AuditService;
import top.focess.keystead.server.crypto.ServerCryptoAlgorithmRegistry;

@Service
public class VaultRecoveryPackageService {

    private final VaultAccessGuard access;
    private final VaultKeyRotationService rotations;
    private final VaultKeyPackageRepository packages;
    private final AuditService audit;
    private final Clock clock;

    VaultRecoveryPackageService(
            @NonNull VaultAccessGuard access,
            @NonNull VaultKeyRotationService rotations,
            @NonNull VaultKeyPackageRepository packages,
            @NonNull AuditService audit,
            @NonNull Clock clock) {
        this.access = access;
        this.rotations = rotations;
        this.packages = packages;
        this.audit = audit;
        this.clock = clock;
    }

    @Transactional
    public @NonNull List<String> store(
            @NonNull String username,
            @NonNull String deviceId,
            @NonNull List<RecoveryDeviceVaultPackage> values) {
        if (!packages.verifiedDeviceExists(username, deviceId)) {
            throw new VaultKeyPackageNotFoundException("Replacement device does not exist");
        }
        Set<String> fingerprints = new HashSet<>();
        List<PendingPackage> pending = new ArrayList<>();
        Instant now = clock.instant();
        for (RecoveryDeviceVaultPackage value : values) {
            if (!fingerprints.add(value.fingerprint())) {
                throw new InvalidVaultKeyPackageRequestException(
                        "Recovery package vault is duplicated");
            }
            if (!ServerCryptoAlgorithmRegistry.isApprovedVaultKeyPackageAlgorithm(
                    value.keyAlgorithm())) {
                throw new InvalidVaultKeyPackageRequestException(
                        "Recovery package algorithm is unsupported");
            }
            String ownerId =
                    access.requireActiveMemberAndResolveOwner(username, value.fingerprint());
            rotations.requireCurrentOrLegacy(ownerId, value.fingerprint(), value.vaultKeyId());
            StoredVaultKeyPackage existing =
                    packages.find(ownerId, value.fingerprint(), username, deviceId).orElse(null);
            pending.add(
                    new PendingPackage(
                            ownerId,
                            new StoredVaultKeyPackage(
                                    ownerId,
                                    value.fingerprint(),
                                    username,
                                    deviceId,
                                    value.vaultKeyId(),
                                    value.keyAlgorithm(),
                                    value.encryptedVaultKey(),
                                    existing == null ? now : existing.createdAt(),
                                    now),
                            existing == null));
        }
        for (PendingPackage value : pending) {
            if (value.insert()) {
                packages.insert(value.keyPackage());
            } else {
                packages.update(value.keyPackage());
            }
            audit.keyPackageStored(
                    value.ownerId(),
                    username,
                    value.keyPackage().fingerprint(),
                    deviceId,
                    value.keyPackage().vaultKeyId(),
                    value.keyPackage().keyAlgorithm());
        }
        return List.copyOf(fingerprints);
    }

    private record PendingPackage(
            @NonNull String ownerId, @NonNull StoredVaultKeyPackage keyPackage, boolean insert) {}
}
