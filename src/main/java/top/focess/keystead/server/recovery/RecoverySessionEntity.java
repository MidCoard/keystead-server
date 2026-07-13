package top.focess.keystead.server.recovery;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

@Entity
@Table(name = "recovery_sessions")
public class RecoverySessionEntity {

    @Id
    @Column(name = "token_hash", nullable = false)
    @NonNull String tokenHash = "";

    @Column(name = "username", nullable = false)
    @NonNull String username = "";

    @Enumerated(EnumType.STRING)
    @Column(name = "authority", nullable = false)
    @NonNull RecoveryAuthority authority = RecoveryAuthority.KIT;

    @Column(name = "enrollment_id")
    @Nullable String enrollmentId;

    @Column(name = "generation")
    @Nullable Long generation;

    @Column(name = "request_id")
    @Nullable String requestId;

    @Column(name = "expires_at", nullable = false)
    @NonNull Instant expiresAt = Instant.EPOCH;

    @Column(name = "consumed_at")
    @Nullable Instant consumedAt;

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;

    protected RecoverySessionEntity() {}
}
