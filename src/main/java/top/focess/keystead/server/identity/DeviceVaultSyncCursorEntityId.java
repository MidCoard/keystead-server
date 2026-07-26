package top.focess.keystead.server.identity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

@Embeddable
public final class DeviceVaultSyncCursorEntityId implements Serializable {

    @Column(name = "owner_id", nullable = false)
    @NonNull String ownerId = "";

    @Column(name = "fingerprint", nullable = false)
    @NonNull String fingerprint = "";

    @Column(name = "device_id", nullable = false)
    @NonNull String deviceId = "";

    public DeviceVaultSyncCursorEntityId() {}

    public DeviceVaultSyncCursorEntityId(
            @NonNull String ownerId, @NonNull String fingerprint, @NonNull String deviceId) {
        this.ownerId = ownerId;
        this.fingerprint = fingerprint;
        this.deviceId = deviceId;
    }

    @Override
    public boolean equals(@NonNull Object object) {
        if (this == object) {
            return true;
        }
        if (!(object instanceof DeviceVaultSyncCursorEntityId other)) {
            return false;
        }
        return ownerId.equals(other.ownerId)
                && fingerprint.equals(other.fingerprint)
                && deviceId.equals(other.deviceId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ownerId, fingerprint, deviceId);
    }
}
