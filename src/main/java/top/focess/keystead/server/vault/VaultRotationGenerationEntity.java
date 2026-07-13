package top.focess.keystead.server.vault;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

@Entity
@Table(
        name = "vault_rotation_generations",
        uniqueConstraints = {
            @UniqueConstraint(
                    name = "uq_vault_rotation_generation_binding",
                    columnNames = {"generation_id", "owner_id", "vault_id"}),
            @UniqueConstraint(
                    name = "ux_vault_rotation_pending_generation",
                    columnNames = {"owner_id", "vault_id", "pending_marker"})
        })
public class VaultRotationGenerationEntity {

    @Id
    @Column(name = "generation_id", nullable = false)
    @NonNull String generationId = "";

    @Column(name = "owner_id", nullable = false)
    @NonNull String ownerId = "";

    @Column(name = "vault_id", nullable = false)
    @NonNull String vaultId = "";

    @Column(name = "source_key_id")
    @Nullable String sourceKeyId;

    @Column(name = "target_key_id", nullable = false)
    @NonNull String targetKeyId = "";

    @Enumerated(EnumType.STRING)
    @Column(name = "state", nullable = false)
    @NonNull VaultRotationGenerationState state = VaultRotationGenerationState.OPEN;

    @Column(name = "initiator_id", nullable = false)
    @NonNull String initiatorId = "";

    @Column(name = "lifecycle_version", nullable = false)
    long lifecycleVersion = 1L;

    @Enumerated(EnumType.STRING)
    @Column(name = "prior_lifecycle_state", nullable = false)
    @NonNull VaultKeyLifecycleState priorLifecycleState = VaultKeyLifecycleState.STABLE;

    @Column(name = "pending_marker")
    @Nullable String pendingMarker = "P";

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;

    @Column(name = "updated_at", nullable = false)
    @NonNull Instant updatedAt = Instant.EPOCH;

    protected VaultRotationGenerationEntity() {}
}
