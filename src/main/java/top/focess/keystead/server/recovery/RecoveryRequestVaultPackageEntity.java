package top.focess.keystead.server.recovery;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;

@Entity
@Table(name = "recovery_device_request_packages")
public class RecoveryRequestVaultPackageEntity {

    @EmbeddedId @NonNull RecoveryRequestVaultPackageId id = new RecoveryRequestVaultPackageId();

    @Column(name = "vault_key_id", nullable = false)
    @NonNull String vaultKeyId = "";

    @Column(name = "key_algorithm", nullable = false)
    @NonNull String keyAlgorithm = "";

    @Column(name = "encrypted_vault_key", nullable = false, columnDefinition = "text")
    @NonNull String encryptedVaultKey = "";

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;

    protected RecoveryRequestVaultPackageEntity() {}
}
