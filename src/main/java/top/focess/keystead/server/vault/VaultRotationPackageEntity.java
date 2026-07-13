package top.focess.keystead.server.vault;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

@Entity
@IdClass(VaultRotationPackageEntity.Key.class)
@Table(name = "vault_rotation_packages")
public class VaultRotationPackageEntity {

    @Id
    @Column(name = "generation_id", nullable = false)
    @NonNull String generationId = "";

    @Id
    @Column(name = "target_id", nullable = false)
    @NonNull String targetId = "";

    @Column(name = "key_algorithm", nullable = false)
    @NonNull String keyAlgorithm = "";

    @Column(name = "encrypted_vault_key", nullable = false, columnDefinition = "text")
    @NonNull String encryptedVaultKey = "";

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;

    protected VaultRotationPackageEntity() {}

    @NonNull Key id() {
        return new Key(generationId, targetId);
    }

    public static final class Key implements Serializable {
        @NonNull public String generationId = "";
        @NonNull public String targetId = "";

        public Key() {}

        public Key(@NonNull String generationId, @NonNull String targetId) {
            this.generationId = generationId;
            this.targetId = targetId;
        }

        @Override
        public boolean equals(@Nullable Object object) {
            return object instanceof Key other
                    && generationId.equals(other.generationId)
                    && targetId.equals(other.targetId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(generationId, targetId);
        }
    }
}
