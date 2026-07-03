package top.focess.keystead.server.record;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

@Embeddable
public final class EncryptedRecordEntityId implements Serializable {

    @Column(name = "owner_id", nullable = false)
    @NonNull String ownerId = "";

    @Column(name = "vault_id", nullable = false)
    @NonNull String vaultId = "";

    @Column(name = "secret_id", nullable = false)
    @NonNull String secretId = "";

    public EncryptedRecordEntityId() {}

    public EncryptedRecordEntityId(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String secretId) {
        this.ownerId = ownerId;
        this.vaultId = vaultId;
        this.secretId = secretId;
    }

    @Override
    public boolean equals(@NonNull Object object) {
        if (this == object) {
            return true;
        }
        if (!(object instanceof EncryptedRecordEntityId other)) {
            return false;
        }
        return ownerId.equals(other.ownerId)
                && vaultId.equals(other.vaultId)
                && secretId.equals(other.secretId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ownerId, vaultId, secretId);
    }
}
