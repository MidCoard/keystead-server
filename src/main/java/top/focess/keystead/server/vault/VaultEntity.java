package top.focess.keystead.server.vault;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;

@Entity
@Table(name = "vaults", indexes = @Index(name = "idx_vaults_owner", columnList = "owner_id"))
public class VaultEntity {

    @EmbeddedId @NonNull VaultEntityId id = new VaultEntityId();

    @Column(name = "encrypted_metadata", nullable = false, columnDefinition = "text")
    @NonNull String encryptedMetadata = "";

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;

    @Column(name = "updated_at", nullable = false)
    @NonNull Instant updatedAt = Instant.EPOCH;

    protected VaultEntity() {}

    private VaultEntity(@NonNull StoredVault vault) {
        this.id = new VaultEntityId(vault.ownerId(), vault.vaultId());
        this.encryptedMetadata = vault.encryptedMetadata();
        this.createdAt = vault.createdAt();
        this.updatedAt = vault.updatedAt();
    }

    static @NonNull VaultEntity from(@NonNull StoredVault vault) {
        return new VaultEntity(vault);
    }

    @NonNull StoredVault toStored() {
        return new StoredVault(id.ownerId, id.vaultId, encryptedMetadata, createdAt, updatedAt);
    }
}
