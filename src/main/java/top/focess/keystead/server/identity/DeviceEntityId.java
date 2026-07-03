package top.focess.keystead.server.identity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

@Embeddable
public final class DeviceEntityId implements Serializable {

    @Column(name = "owner_id", nullable = false)
    @NonNull String ownerId = "";

    @Column(name = "device_id", nullable = false)
    @NonNull String deviceId = "";

    public DeviceEntityId() {}

    public DeviceEntityId(@NonNull String ownerId, @NonNull String deviceId) {
        this.ownerId = ownerId;
        this.deviceId = deviceId;
    }

    @Override
    public boolean equals(@NonNull Object object) {
        if (this == object) {
            return true;
        }
        if (!(object instanceof DeviceEntityId other)) {
            return false;
        }
        return ownerId.equals(other.ownerId) && deviceId.equals(other.deviceId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ownerId, deviceId);
    }
}
