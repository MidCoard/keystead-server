package top.focess.keystead.server.identity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

@Embeddable
public final class DeviceChallengeEntityId implements Serializable {

    @Column(name = "owner_id", nullable = false)
    @NonNull String ownerId = "";

    @Column(name = "device_id", nullable = false)
    @NonNull String deviceId = "";

    @Column(name = "challenge_id", nullable = false)
    @NonNull String challengeId = "";

    public DeviceChallengeEntityId() {}

    public DeviceChallengeEntityId(
            @NonNull String ownerId, @NonNull String deviceId, @NonNull String challengeId) {
        this.ownerId = ownerId;
        this.deviceId = deviceId;
        this.challengeId = challengeId;
    }

    @Override
    public boolean equals(@NonNull Object object) {
        if (this == object) {
            return true;
        }
        if (!(object instanceof DeviceChallengeEntityId other)) {
            return false;
        }
        return ownerId.equals(other.ownerId)
                && deviceId.equals(other.deviceId)
                && challengeId.equals(other.challengeId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ownerId, deviceId, challengeId);
    }
}
