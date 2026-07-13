package top.focess.keystead.server.vault;

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
@Table(name = "vault_key_states")
public class VaultKeyStateEntity {

    @EmbeddedId @NonNull VaultEntityId id = new VaultEntityId();

    @Column(name = "current_vault_key_id")
    @Nullable String currentVaultKeyId;

    @Enumerated(EnumType.STRING)
    @Column(name = "lifecycle_state", nullable = false)
    @NonNull VaultKeyLifecycleState lifecycleState = VaultKeyLifecycleState.STABLE;

    @Column(name = "lifecycle_version", nullable = false)
    long lifecycleVersion = 1L;

    @Column(name = "pending_generation_id")
    @Nullable String pendingGenerationId;

    @Column(name = "updated_at", nullable = false)
    @NonNull Instant updatedAt = Instant.EPOCH;

    protected VaultKeyStateEntity() {}
}
