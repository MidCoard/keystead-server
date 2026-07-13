package top.focess.keystead.server.recovery;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.io.Serializable;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

@Embeddable
public final class RecoveryEnrollmentId implements Serializable {

    @Column(name = "username", nullable = false)
    @NonNull String username = "";

    @Column(name = "enrollment_id", nullable = false)
    @NonNull String enrollmentId = "";

    @Column(name = "generation", nullable = false)
    long generation;

    public RecoveryEnrollmentId() {}

    public RecoveryEnrollmentId(
            @NonNull String username, @NonNull String enrollmentId, long generation) {
        this.username = username;
        this.enrollmentId = enrollmentId;
        this.generation = generation;
    }

    @Override
    public boolean equals(@NonNull Object object) {
        return object instanceof RecoveryEnrollmentId other
                && username.equals(other.username)
                && enrollmentId.equals(other.enrollmentId)
                && generation == other.generation;
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, enrollmentId, generation);
    }
}
