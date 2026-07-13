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
@Table(name = "recovery_device_requests")
public class RecoveryRequestEntity {

    @Id
    @Column(name = "request_id", nullable = false)
    @NonNull String requestId = "";

    @Column(name = "username", nullable = false)
    @NonNull String username = "";

    @Column(name = "nonce", nullable = false)
    @NonNull String nonce = "";

    @Column(name = "fingerprint", nullable = false)
    @NonNull String fingerprint = "";

    @Column(name = "device_id", nullable = false)
    @NonNull String deviceId = "";

    @Column(name = "proof_key_algorithm", nullable = false)
    @NonNull String proofKeyAlgorithm = "";

    @Column(name = "proof_public_key", nullable = false, columnDefinition = "text")
    @NonNull String proofPublicKey = "";

    @Column(name = "wrapping_key_algorithm", nullable = false)
    @NonNull String wrappingKeyAlgorithm = "";

    @Column(name = "wrapping_public_key", nullable = false, columnDefinition = "text")
    @NonNull String wrappingPublicKey = "";

    @Enumerated(EnumType.STRING)
    @Column(name = "state", nullable = false)
    @NonNull RecoveryRequestState state = RecoveryRequestState.PENDING;

    @Column(name = "expires_at", nullable = false)
    @NonNull Instant expiresAt = Instant.EPOCH;

    @Column(name = "approved_by_device_id")
    @Nullable String approvedByDeviceId;

    @Column(name = "approved_at")
    @Nullable Instant approvedAt;

    @Column(name = "consumed_at")
    @Nullable Instant consumedAt;

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;

    protected RecoveryRequestEntity() {}
}
