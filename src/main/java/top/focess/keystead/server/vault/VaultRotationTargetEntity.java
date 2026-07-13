package top.focess.keystead.server.vault;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

@Entity
@IdClass(VaultRotationTargetEntity.Key.class)
@Table(name = "vault_rotation_targets")
public class VaultRotationTargetEntity {

    @Id
    @Column(name = "generation_id", nullable = false)
    @NonNull String generationId = "";

    @Id
    @Column(name = "target_id", nullable = false)
    @NonNull String targetId = "";

    @Enumerated(EnumType.STRING)
    @Column(name = "target_type", nullable = false)
    @NonNull VaultRotationTargetType targetType = VaultRotationTargetType.DEVICE;

    @Column(name = "recipient_id")
    @Nullable String recipientId;

    @Column(name = "device_id")
    @Nullable String deviceId;

    @Column(name = "principal_id")
    @Nullable String principalId;

    @Column(name = "enrollment_id")
    @Nullable String enrollmentId;

    @Column(name = "recovery_generation")
    @Nullable Long recoveryGeneration;

    @Column(name = "key_algorithm", nullable = false)
    @NonNull String keyAlgorithm = "";

    @Column(name = "public_key", nullable = false, columnDefinition = "text")
    @NonNull String publicKey = "";

    @Column(name = "required", nullable = false)
    boolean required;

    protected VaultRotationTargetEntity() {}

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
