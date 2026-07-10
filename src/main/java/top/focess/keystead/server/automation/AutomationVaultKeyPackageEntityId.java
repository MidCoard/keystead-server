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

    @Column(name = "vault_id", nullable = false)
    @NonNull String vaultId = "";

    @Column(name = "principal_id", nullable = false)
    @NonNull String principalId = "";

    public AutomationVaultKeyPackageEntityId() {}

    public AutomationVaultKeyPackageEntityId(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String principalId) {
        this.ownerId = ownerId;
        this.vaultId = vaultId;
        this.principalId = principalId;
    }

    @Override
    public boolean equals(@NonNull Object object) {
        return object instanceof AutomationVaultKeyPackageEntityId other
                && ownerId.equals(other.ownerId)
                && vaultId.equals(other.vaultId)
                && principalId.equals(other.principalId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ownerId, vaultId, principalId);
    }
}
