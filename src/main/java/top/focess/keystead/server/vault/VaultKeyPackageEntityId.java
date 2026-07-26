package top.focess.keystead.server.vault;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

@Embeddable
public final class VaultKeyPackageEntityId implements Serializable {

    @Column(name = "owner_id", nullable = false)
    @NonNull String ownerId = "";

    @Column(name = "fingerprint", nullable = false)
    @NonNull String fingerprint = "";

    @Column(name = "recipient_id", nullable = false)
    @NonNull String recipientId = "";

    @Column(name = "device_id", nullable = false)
    @NonNull String deviceId = "";

    public VaultKeyPackageEntityId() {}

    public VaultKeyPackageEntityId(
            @NonNull String ownerId, @NonNull String fingerprint, @NonNull String deviceId) {
        this(ownerId, fingerprint, ownerId, deviceId);
    }

    public VaultKeyPackageEntityId(
            @NonNull String ownerId,
            @NonNull String fingerprint,
            @NonNull String recipientId,
            @NonNull String deviceId) {
        this.ownerId = ownerId;
        this.fingerprint = fingerprint;
        this.recipientId = recipientId;
        this.deviceId = deviceId;
    }

    @Override
    public boolean equals(@NonNull Object object) {
        if (this == object) {
            return true;
        }
        if (!(object instanceof VaultKeyPackageEntityId other)) {
            return false;
        }
        return ownerId.equals(other.ownerId)
                && fingerprint.equals(other.fingerprint)
                && recipientId.equals(other.recipientId)
                && deviceId.equals(other.deviceId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ownerId, fingerprint, recipientId, deviceId);
    }
}
