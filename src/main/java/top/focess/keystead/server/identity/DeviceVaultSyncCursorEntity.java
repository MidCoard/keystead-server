package top.focess.keystead.server.identity;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;

@Entity
@Table(
        name = "device_vault_sync_cursors",
        indexes =
                @Index(
                        name = "idx_device_vault_sync_cursors_owner_vault_revision",
                        columnList = "owner_id, vault_id, pulled_revision"))
public class DeviceVaultSyncCursorEntity {

    @EmbeddedId @NonNull DeviceVaultSyncCursorEntityId id = new DeviceVaultSyncCursorEntityId();

    @Column(name = "pulled_revision", nullable = false)
    long pulledRevision;

    @Column(name = "updated_at", nullable = false)
    @NonNull Instant updatedAt = Instant.EPOCH;

    protected DeviceVaultSyncCursorEntity() {}

    private DeviceVaultSyncCursorEntity(@NonNull StoredDeviceVaultSyncCursor cursor) {
        this.id =
                new DeviceVaultSyncCursorEntityId(
                        cursor.ownerId(), cursor.vaultId(), cursor.deviceId());
        this.pulledRevision = cursor.pulledRevision();
        this.updatedAt = cursor.updatedAt();
    }

    static @NonNull DeviceVaultSyncCursorEntity from(@NonNull StoredDeviceVaultSyncCursor cursor) {
        return new DeviceVaultSyncCursorEntity(cursor);
    }

    @NonNull StoredDeviceVaultSyncCursor toStored() {
        return new StoredDeviceVaultSyncCursor(
                id.ownerId, id.vaultId, id.deviceId, pulledRevision, updatedAt);
    }
}
