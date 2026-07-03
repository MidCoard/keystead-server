package top.focess.keystead.server.identity;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

@Entity
@Table(name = "device_challenges")
public class DeviceChallengeEntity {

    @EmbeddedId @NonNull DeviceChallengeEntityId id = new DeviceChallengeEntityId();

    @Column(name = "nonce", nullable = false)
    @NonNull String nonce = "";

    @Column(name = "expires_at", nullable = false)
    @NonNull Instant expiresAt = Instant.EPOCH;

    @Column(name = "used_at")
    @Nullable Instant usedAt;

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;

    protected DeviceChallengeEntity() {}

    private DeviceChallengeEntity(@NonNull StoredDeviceChallenge challenge) {
        this.id =
                new DeviceChallengeEntityId(
                        challenge.ownerId(), challenge.deviceId(), challenge.challengeId());
        this.nonce = challenge.nonce();
        this.expiresAt = challenge.expiresAt();
        this.usedAt = challenge.usedAt();
        this.createdAt = challenge.createdAt();
    }

    static @NonNull DeviceChallengeEntity from(@NonNull StoredDeviceChallenge challenge) {
        return new DeviceChallengeEntity(challenge);
    }

    @NonNull StoredDeviceChallenge toStored() {
        return new StoredDeviceChallenge(
                id.ownerId, id.deviceId, id.challengeId, nonce, expiresAt, usedAt, createdAt);
    }
}
