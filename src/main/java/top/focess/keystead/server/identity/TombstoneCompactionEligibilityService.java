package top.focess.keystead.server.identity;

import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.server.vault.VaultAccessGuard;

@Service
class TombstoneCompactionEligibilityService {

    private final DeviceRepository devices;
    private final DeviceVaultSyncCursorRepository cursors;
    private final VaultAccessGuard vaultAccess;

    TombstoneCompactionEligibilityService(
            @NonNull DeviceRepository devices,
            @NonNull DeviceVaultSyncCursorRepository cursors,
            @NonNull VaultAccessGuard vaultAccess) {
        this.devices = devices;
        this.cursors = cursors;
        this.vaultAccess = vaultAccess;
    }

    @Transactional(readOnly = true)
    boolean isEligible(@NonNull String ownerId, @NonNull String vaultId, long tombstoneRevision) {
        if (tombstoneRevision <= 0) {
            throw new IllegalArgumentException("tombstoneRevision must be positive");
        }
        vaultAccess.requireOwnedVault(ownerId, vaultId);
        List<StoredDevice> activeDevices =
                devices.list(ownerId).stream()
                        .filter(device -> device.verifiedAt() != null)
                        .filter(device -> device.revokedAt() == null)
                        .toList();
        if (activeDevices.isEmpty()) {
            return false;
        }
        return activeDevices.stream()
                .allMatch(
                        device ->
                                cursors.find(ownerId, vaultId, device.deviceId())
                                        .map(cursor -> cursor.pulledRevision() >= tombstoneRevision)
                                        .orElse(false));
    }
}
