package top.focess.keystead.server.vault;

import java.time.Instant;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class VaultDeviceRevocationService {

    private final VaultKeyPackageRepository keyPackages;
    private final VaultKeyLifecycleService lifecycle;

    VaultDeviceRevocationService(
            @NonNull VaultKeyPackageRepository keyPackages,
            @NonNull VaultKeyLifecycleService lifecycle) {
        this.keyPackages = keyPackages;
        this.lifecycle = lifecycle;
    }

    @Transactional
    public void revokePackages(
            @NonNull String ownerId, @NonNull String deviceId, @NonNull Instant now) {
        List<AffectedVault> affected =
                keyPackages.listCurrentForDevice(ownerId, deviceId).stream()
                        .map(value -> new AffectedVault(value.id.ownerId, value.id.vaultId))
                        .distinct()
                        .toList();
        keyPackages.deleteForDevice(ownerId, deviceId);
        for (AffectedVault vault : affected) {
            lifecycle.requireRotation(
                    vault.ownerId, ownerId, vault.vaultId, "DEVICE_REVOKED", deviceId, now);
        }
    }

    private record AffectedVault(@NonNull String ownerId, @NonNull String vaultId) {}
}
