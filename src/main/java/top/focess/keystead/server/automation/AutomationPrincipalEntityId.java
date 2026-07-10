package top.focess.keystead.server.automation;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

@Embeddable
public final class AutomationPrincipalEntityId implements Serializable {

    @Column(name = "owner_id", nullable = false)
    @NonNull String ownerId = "";

    @Column(name = "principal_id", nullable = false)
    @NonNull String principalId = "";

    public AutomationPrincipalEntityId() {}

    public AutomationPrincipalEntityId(@NonNull String ownerId, @NonNull String principalId) {
        this.ownerId = ownerId;
        this.principalId = principalId;
    }

    @Override
    public boolean equals(@NonNull Object object) {
        return object instanceof AutomationPrincipalEntityId other
                && ownerId.equals(other.ownerId)
                && principalId.equals(other.principalId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ownerId, principalId);
    }
}
