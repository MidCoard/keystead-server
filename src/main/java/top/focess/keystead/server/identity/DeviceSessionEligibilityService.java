package top.focess.keystead.server.identity;

import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DeviceSessionEligibilityService {

    private final DeviceRepository devices;

    DeviceSessionEligibilityService(@NonNull DeviceRepository devices) {
        this.devices = devices;
    }

    @Transactional(readOnly = true)
    public boolean canStartSession(@NonNull String ownerId, @NonNull String deviceId) {
        return devices.find(ownerId, deviceId)
                .filter(device -> device.verifiedAt() != null)
                .filter(device -> device.revokedAt() == null)
                .isPresent();
    }
}
