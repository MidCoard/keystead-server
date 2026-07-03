package top.focess.keystead.server.vault;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.server.crypto.ServerCryptoAlgorithmRegistry;
import top.focess.keystead.server.crypto.UnsupportedCryptoAlgorithmException;

@Service
class VaultKeyPackageService {

    private final VaultAccessGuard accessGuard;
    private final VaultKeyPackageRepository keyPackages;
    private final Clock clock;

    VaultKeyPackageService(
            @NonNull VaultAccessGuard accessGuard,
            @NonNull VaultKeyPackageRepository keyPackages,
            @NonNull Clock clock) {
        this.accessGuard = accessGuard;
        this.keyPackages = keyPackages;
        this.clock = clock;
    }

    @Transactional
    void put(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull String deviceId,
            @NonNull VaultKeyPackageRequest request) {
        if (!ServerCryptoAlgorithmRegistry.isApprovedVaultKeyPackageAlgorithm(
                request.keyAlgorithm())) {
            throw new UnsupportedCryptoAlgorithmException(
                    "Unsupported vault key package algorithm");
        }
        requireVaultAndDevice(ownerId, vaultId, deviceId);
        Instant now = clock.instant();
        Instant createdAt =
                keyPackages
                        .find(ownerId, vaultId, deviceId)
                        .map(StoredVaultKeyPackage::createdAt)
                        .orElse(now);
        keyPackages.upsert(
                new StoredVaultKeyPackage(
                        ownerId,
                        vaultId,
                        deviceId,
                        request.keyAlgorithm(),
                        request.encryptedVaultKey(),
                        createdAt,
                        now));
    }

    @Transactional(readOnly = true)
    @NonNull List<VaultKeyPackageResponse> list(@NonNull String ownerId, @NonNull String vaultId) {
        accessGuard.requireOwnedVault(ownerId, vaultId);
        return keyPackages.list(ownerId, vaultId).stream()
                .map(VaultKeyPackageResponse::from)
                .toList();
    }

    private void requireVaultAndDevice(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String deviceId) {
        accessGuard.requireOwnedVault(ownerId, vaultId);
        if (!keyPackages.verifiedDeviceExists(ownerId, deviceId)) {
            throw new VaultKeyPackageNotFoundException("Device does not exist");
        }
    }
}
