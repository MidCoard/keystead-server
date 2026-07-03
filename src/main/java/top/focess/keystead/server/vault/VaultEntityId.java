package top.focess.keystead.server.vault;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

@Embeddable
public final class VaultEntityId implements Serializable {

    @Column(name = "owner_id", nullable = false)
    @NonNull String ownerId = "";

    @Column(name = "vault_id", nullable = false)
    @NonNull String vaultId = "";

    public VaultEntityId() {}

    public VaultEntityId(@NonNull String ownerId, @NonNull String vaultId) {
        this.ownerId = ownerId;
        this.vaultId = vaultId;
    }

    @Override
    public boolean equals(@NonNull Object object) {
        if (this == object) {
            return true;
        }
        if (!(object instanceof VaultEntityId other)) {
            return false;
        }
        return ownerId.equals(other.ownerId) && vaultId.equals(other.vaultId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ownerId, vaultId);
    }
}
