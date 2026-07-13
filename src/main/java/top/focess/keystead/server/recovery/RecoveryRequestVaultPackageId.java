package top.focess.keystead.server.recovery;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

@Embeddable
public final class RecoveryRequestVaultPackageId implements Serializable {

    @Column(name = "request_id", nullable = false)
    @NonNull String requestId = "";

    @Column(name = "vault_id", nullable = false)
    @NonNull String vaultId = "";

    public RecoveryRequestVaultPackageId() {}

    public RecoveryRequestVaultPackageId(@NonNull String requestId, @NonNull String vaultId) {
        this.requestId = requestId;
        this.vaultId = vaultId;
    }

    @Override
    public boolean equals(@NonNull Object object) {
        return object instanceof RecoveryRequestVaultPackageId other
                && requestId.equals(other.requestId)
                && vaultId.equals(other.vaultId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(requestId, vaultId);
    }
}
