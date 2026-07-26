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

    @Column(name = "fingerprint", nullable = false)
    @NonNull String fingerprint = "";

    public RecoveryRequestVaultPackageId() {}

    public RecoveryRequestVaultPackageId(@NonNull String requestId, @NonNull String fingerprint) {
        this.requestId = requestId;
        this.fingerprint = fingerprint;
    }

    @Override
    public boolean equals(@NonNull Object object) {
        return object instanceof RecoveryRequestVaultPackageId other
                && requestId.equals(other.requestId)
                && fingerprint.equals(other.fingerprint);
    }

    @Override
    public int hashCode() {
        return Objects.hash(requestId, fingerprint);
    }
}
