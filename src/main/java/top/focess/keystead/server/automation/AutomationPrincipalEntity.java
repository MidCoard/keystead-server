package top.focess.keystead.server.automation;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

@Entity
@Table(name = "automation_principals")
public class AutomationPrincipalEntity {

    @EmbeddedId @NonNull AutomationPrincipalEntityId id = new AutomationPrincipalEntityId();

    @Column(name = "public_key_algorithm", nullable = false)
    @NonNull String publicKeyAlgorithm = "";

    @Column(name = "public_key", nullable = false, columnDefinition = "text")
    @NonNull String publicKey = "";

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;

    @Column(name = "updated_at", nullable = false)
    @NonNull Instant updatedAt = Instant.EPOCH;

    @Column(name = "revoked_at")
    @Nullable Instant revokedAt;

    protected AutomationPrincipalEntity() {}

    private AutomationPrincipalEntity(@NonNull AutomationPrincipal principal) {
        this.id = new AutomationPrincipalEntityId(principal.ownerId(), principal.principalId());
        this.publicKeyAlgorithm = principal.publicKeyAlgorithm();
        this.publicKey = principal.publicKey();
        this.createdAt = principal.createdAt();
        this.updatedAt = principal.updatedAt();
        this.revokedAt = principal.revokedAt();
    }

    static @NonNull AutomationPrincipalEntity from(@NonNull AutomationPrincipal principal) {
        return new AutomationPrincipalEntity(principal);
    }

    @NonNull AutomationPrincipal toStored() {
        return new AutomationPrincipal(
                id.ownerId,
                id.principalId,
                publicKeyAlgorithm,
                publicKey,
                createdAt,
                updatedAt,
                revokedAt);
    }
}
