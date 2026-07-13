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

    @Column(name = "vault_id", nullable = false)
    @NonNull String vaultId = "";

    public RecoveryVaultPackageId() {}

    public RecoveryVaultPackageId(
            @NonNull String username,
            @NonNull String enrollmentId,
            long generation,
            @NonNull String vaultId) {
        this.username = username;
        this.enrollmentId = enrollmentId;
        this.generation = generation;
        this.vaultId = vaultId;
    }

    @Override
    public boolean equals(@NonNull Object object) {
        return object instanceof RecoveryVaultPackageId other
                && username.equals(other.username)
                && enrollmentId.equals(other.enrollmentId)
                && generation == other.generation
                && vaultId.equals(other.vaultId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, enrollmentId, generation, vaultId);
    }
}
