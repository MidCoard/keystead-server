package top.focess.keystead.server.vault;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

@Embeddable
public final class VaultMemberEntityId implements Serializable {

    @Column(name = "vault_id", nullable = false)
    @NonNull String vaultId = "";

    @Column(name = "user_id", nullable = false)
    @NonNull String userId = "";

    public VaultMemberEntityId() {}

    public VaultMemberEntityId(@NonNull String vaultId, @NonNull String userId) {
        this.vaultId = vaultId;
        this.userId = userId;
    }

    @Override
    public boolean equals(@NonNull Object object) {
        return object instanceof VaultMemberEntityId other
                && vaultId.equals(other.vaultId)
                && userId.equals(other.userId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(vaultId, userId);
    }
}
