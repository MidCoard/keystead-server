package top.focess.keystead.server.vault;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;

@Entity
@Table(name = "vault_key_rotations")
public class VaultKeyRotationEntity {
    @EmbeddedId @NonNull VaultEntityId id = new VaultEntityId();

    @Column(name = "vault_key_id", nullable = false)
    @NonNull String vaultKeyId = "";

    @Column(name = "rotated_at", nullable = false)
    @NonNull Instant rotatedAt = Instant.EPOCH;

    protected VaultKeyRotationEntity() {}

    private VaultKeyRotationEntity(@NonNull VaultKeyRotation value) {
        id = new VaultEntityId(value.ownerId(), value.vaultId());
        vaultKeyId = value.vaultKeyId();
        rotatedAt = value.rotatedAt();
    }

    static @NonNull VaultKeyRotationEntity from(@NonNull VaultKeyRotation value) {
        return new VaultKeyRotationEntity(value);
    }

    @NonNull VaultKeyRotation toStored() {
        return new VaultKeyRotation(id.ownerId, id.vaultId, vaultKeyId, rotatedAt);
    }
}
