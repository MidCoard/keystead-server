package top.focess.keystead.server.recovery;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

@Entity
@Table(name = "recovery_challenges")
public class RecoveryChallengeEntity {

    @Id
    @Column(name = "challenge_id", nullable = false)
    @NonNull String challengeId = "";

    @Column(name = "username", nullable = false)
    @NonNull String username = "";

    @Column(name = "enrollment_id")
    @Nullable String enrollmentId;

    @Column(name = "generation")
    @Nullable Long generation;

    @Column(name = "expires_at", nullable = false)
    @NonNull Instant expiresAt = Instant.EPOCH;

    @Column(name = "attempts", nullable = false)
    int attempts;

    @Column(name = "consumed_at")
    @Nullable Instant consumedAt;

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;

    protected RecoveryChallengeEntity() {}
}
