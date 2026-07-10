package top.focess.keystead.server.identity;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import java.time.Clock;
import java.util.Optional;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.server.vault.VaultAccessGuard;

@Service
class DeviceVaultSyncCursorService {

    private final DeviceVaultSyncCursorRepository cursors;
    private final DeviceSessionEligibilityService deviceEligibility;
    private final VaultAccessGuard vaultAccess;
    private final Clock clock;
    private final Validator validator;

    DeviceVaultSyncCursorService(
            @NonNull DeviceVaultSyncCursorRepository cursors,
            @NonNull DeviceSessionEligibilityService deviceEligibility,
            @NonNull VaultAccessGuard vaultAccess,
            @NonNull Clock clock,
            @NonNull Validator validator) {
        this.cursors = cursors;
        this.deviceEligibility = deviceEligibility;
        this.vaultAccess = vaultAccess;
        this.clock = clock;
        this.validator = validator;
    }

    @Transactional
    void acknowledgePulledRevision(
            @NonNull String ownerId,
            @NonNull String deviceId,
            @NonNull String vaultId,
            @NonNull DeviceVaultSyncCursorRequest request) {
        vaultAccess.requireOwnedVault(ownerId, vaultId);
        requireEligibleDevice(ownerId, deviceId);
        validate(request);
        Optional<StoredDeviceVaultSyncCursor> existing = cursors.find(ownerId, vaultId, deviceId);
        existing.ifPresent(
                cursor -> {
                    if (request.pulledRevision() < cursor.pulledRevision()) {
                        throw new InvalidDeviceVaultSyncCursorRequestException(
                                "pulledRevision must not move backwards");
                    }
                });
        StoredDeviceVaultSyncCursor next =
                new StoredDeviceVaultSyncCursor(
                        ownerId, vaultId, deviceId, request.pulledRevision(), clock.instant());
        if (existing.isPresent()) {
            cursors.update(next);
        } else {
            cursors.insert(next);
        }
    }

    private void requireEligibleDevice(@NonNull String ownerId, @NonNull String deviceId) {
        if (!deviceEligibility.canStartSession(ownerId, deviceId)) {
            throw new DeviceNotFoundException("Device does not exist");
        }
    }

    private void validate(@NonNull DeviceVaultSyncCursorRequest request) {
        Set<ConstraintViolation<DeviceVaultSyncCursorRequest>> violations =
                validator.validate(request);
        if (!violations.isEmpty()) {
            throw new InvalidDeviceVaultSyncCursorRequestException(
                    violations.iterator().next().getPropertyPath() + " is invalid");
        }
    }
}
