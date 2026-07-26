package top.focess.keystead.server.recovery;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

@Embeddable
public final class RecoveryVaultPackageId implements Serializable {

    @Column(name = "username", nullable = false)
    @NonNull String username = "";

    @Column(name = "enrollment_id", nullable = false)
    @NonNull String enrollmentId = "";

    @Column(name = "generation", nullable = false)
    long generation;

    @Column(name = "fingerprint", nullable = false)
    @NonNull String fingerprint = "";

    public RecoveryVaultPackageId() {}

    public RecoveryVaultPackageId(
            @NonNull String username,
            @NonNull String enrollmentId,
            long generation,
            @NonNull String fingerprint) {
        this.username = username;
        this.enrollmentId = enrollmentId;
        this.generation = generation;
        this.fingerprint = fingerprint;
    }

    @Override
    public boolean equals(@NonNull Object object) {
        return object instanceof RecoveryVaultPackageId other
                && username.equals(other.username)
                && enrollmentId.equals(other.enrollmentId)
                && generation == other.generation
                && fingerprint.equals(other.fingerprint);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, enrollmentId, generation, fingerprint);
    }
}
