package top.focess.keystead.server.record;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;

@Entity
@Table(name = "personal_vaults")
class PersonalVaultEntity {

    @Id
    @Column(name = "owner_id", nullable = false)
    @NonNull String ownerId = "";

    @Column(name = "fingerprint", nullable = false)
    @NonNull String fingerprint = "";

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;

    @Column(name = "updated_at", nullable = false)
    @NonNull Instant updatedAt = Instant.EPOCH;

    protected PersonalVaultEntity() {}

    PersonalVaultEntity(
            @NonNull String ownerId,
            @NonNull String fingerprint,
            @NonNull Instant createdAt,
            @NonNull Instant updatedAt) {
        this.ownerId = ownerId;
        this.fingerprint = fingerprint;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }
}
