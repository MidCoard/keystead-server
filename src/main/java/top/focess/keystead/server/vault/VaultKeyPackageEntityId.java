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

    @Column(name = "vault_id", nullable = false)
    @NonNull String vaultId = "";

    @Column(name = "recipient_id", nullable = false)
    @NonNull String recipientId = "";

    @Column(name = "device_id", nullable = false)
    @NonNull String deviceId = "";

    public VaultKeyPackageEntityId() {}

    public VaultKeyPackageEntityId(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String deviceId) {
        this(ownerId, vaultId, ownerId, deviceId);
    }

    public VaultKeyPackageEntityId(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull String recipientId,
            @NonNull String deviceId) {
        this.ownerId = ownerId;
        this.vaultId = vaultId;
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
                && vaultId.equals(other.vaultId)
                && recipientId.equals(other.recipientId)
                && deviceId.equals(other.deviceId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ownerId, vaultId, recipientId, deviceId);
    }
}
