package top.focess.keystead.server.identity;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

@Entity
@Table(name = "devices")
public class DeviceEntity {

    @EmbeddedId @NonNull DeviceEntityId id = new DeviceEntityId();

    @Column(name = "key_algorithm", nullable = false)
    @NonNull String keyAlgorithm = "";

    @Column(name = "public_key", nullable = false, columnDefinition = "text")
    @NonNull String publicKey = "";

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;

    @Column(name = "verified_at")
    @Nullable Instant verifiedAt;

    @Column(name = "last_seen_at")
    @Nullable Instant lastSeenAt;

    @Column(name = "revoked_at")
    @Nullable Instant revokedAt;

    protected DeviceEntity() {}

    private DeviceEntity(@NonNull StoredDevice device) {
        this.id = new DeviceEntityId(device.ownerId(), device.deviceId());
        this.keyAlgorithm = device.keyAlgorithm();
        this.publicKey = device.publicKey();
        this.createdAt = device.createdAt();
        this.verifiedAt = device.verifiedAt();
        this.lastSeenAt = device.lastSeenAt();
        this.revokedAt = device.revokedAt();
    }

    static @NonNull DeviceEntity from(@NonNull StoredDevice device) {
        return new DeviceEntity(device);
    }

    @NonNull StoredDevice toStored() {
        return new StoredDevice(
                id.ownerId,
                id.deviceId,
                keyAlgorithm,
                publicKey,
                createdAt,
                verifiedAt,
                lastSeenAt,
                revokedAt);
    }
}
