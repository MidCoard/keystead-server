package top.focess.keystead.server.vault;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

@Embeddable
public final class VaultMemberEntityId implements Serializable {

    @Column(name = "fingerprint", nullable = false)
    @NonNull String fingerprint = "";

    @Column(name = "user_id", nullable = false)
    @NonNull String userId = "";

    public VaultMemberEntityId() {}

    public VaultMemberEntityId(@NonNull String fingerprint, @NonNull String userId) {
        this.fingerprint = fingerprint;
        this.userId = userId;
    }

    @Override
    public boolean equals(@NonNull Object object) {
        return object instanceof VaultMemberEntityId other
                && fingerprint.equals(other.fingerprint)
                && userId.equals(other.userId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(fingerprint, userId);
    }
}
