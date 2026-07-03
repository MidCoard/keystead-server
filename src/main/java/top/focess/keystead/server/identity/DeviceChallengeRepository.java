package top.focess.keystead.server.identity;

import java.time.Instant;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface DeviceChallengeRepository
        extends JpaRepository<DeviceChallengeEntity, DeviceChallengeEntityId> {

    default void insert(@NonNull StoredDeviceChallenge challenge) {
        save(DeviceChallengeEntity.from(challenge));
    }

    default @NonNull Optional<StoredDeviceChallenge> find(
            @NonNull String ownerId, @NonNull String deviceId, @NonNull String challengeId) {
        return findById(new DeviceChallengeEntityId(ownerId, deviceId, challengeId))
                .map(DeviceChallengeEntity::toStored);
    }

    @Modifying
    @Query(
            """
            update DeviceChallengeEntity c
               set c.usedAt = :when
             where c.id.ownerId = :ownerId
               and c.id.deviceId = :deviceId
               and c.id.challengeId = :challengeId
            """)
    void markUsed(
            @Param("ownerId") @NonNull String ownerId,
            @Param("deviceId") @NonNull String deviceId,
            @Param("challengeId") @NonNull String challengeId,
            @Param("when") @NonNull Instant when);
}
