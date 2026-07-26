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

    @Column(name = "fingerprint", nullable = false)
    @NonNull String fingerprint = "";

    public VaultEntityId() {}

    public VaultEntityId(@NonNull String ownerId, @NonNull String fingerprint) {
        this.ownerId = ownerId;
        this.fingerprint = fingerprint;
    }

    @Override
    public boolean equals(@NonNull Object object) {
        if (this == object) {
            return true;
        }
        if (!(object instanceof VaultEntityId other)) {
            return false;
        }
        return ownerId.equals(other.ownerId) && fingerprint.equals(other.fingerprint);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ownerId, fingerprint);
    }
}
