package top.focess.keystead.server.recovery;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

@Entity
@Table(name = "recovery_enrollments")
public class RecoveryEnrollmentEntity {

    @EmbeddedId @NonNull RecoveryEnrollmentId id = new RecoveryEnrollmentId();

    @Column(name = "credential_hash", nullable = false)
    @NonNull String credentialHash = "";

    @Column(name = "wrapping_algorithm", nullable = false)
    @NonNull String wrappingAlgorithm = "";

    @Column(name = "wrapping_public_key", nullable = false, columnDefinition = "text")
    @NonNull String wrappingPublicKey = "";

    @Column(name = "encrypted_private_key", nullable = false, columnDefinition = "text")
    @NonNull String encryptedPrivateKey = "";

    @Enumerated(EnumType.STRING)
    @Column(name = "state", nullable = false)
    @NonNull RecoveryEnrollmentState state = RecoveryEnrollmentState.PENDING;

    @Column(name = "lifecycle_marker")
    @Nullable String lifecycleMarker;

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;

    @Column(name = "committed_at")
    @Nullable Instant committedAt;

    @Column(name = "consumed_at")
    @Nullable Instant consumedAt;

    protected RecoveryEnrollmentEntity() {}
}
