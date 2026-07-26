package top.focess.keystead.server.automation;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

@Embeddable
public final class AutomationVaultKeyPackageEntityId implements Serializable {

    @Column(name = "owner_id", nullable = false)
    @NonNull String ownerId = "";

    @Column(name = "fingerprint", nullable = false)
    @NonNull String fingerprint = "";

    @Column(name = "principal_id", nullable = false)
    @NonNull String principalId = "";

    public AutomationVaultKeyPackageEntityId() {}

    public AutomationVaultKeyPackageEntityId(
            @NonNull String ownerId, @NonNull String fingerprint, @NonNull String principalId) {
        this.ownerId = ownerId;
        this.fingerprint = fingerprint;
        this.principalId = principalId;
    }

    @Override
    public boolean equals(@NonNull Object object) {
        return object instanceof AutomationVaultKeyPackageEntityId other
                && ownerId.equals(other.ownerId)
                && fingerprint.equals(other.fingerprint)
                && principalId.equals(other.principalId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ownerId, fingerprint, principalId);
    }
}
