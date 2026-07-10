package top.focess.keystead.server.automation;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;

@Entity
@Table(name = "automation_vault_key_packages")
public class AutomationVaultKeyPackageEntity {

    @EmbeddedId
    @NonNull AutomationVaultKeyPackageEntityId id = new AutomationVaultKeyPackageEntityId();

    @Column(name = "vault_key_id", nullable = false)
    @NonNull String vaultKeyId = "";

    @Column(name = "key_algorithm", nullable = false)
    @NonNull String keyAlgorithm = "";

    @Column(name = "encrypted_vault_key", nullable = false, columnDefinition = "text")
    @NonNull String encryptedVaultKey = "";

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;

    @Column(name = "updated_at", nullable = false)
    @NonNull Instant updatedAt = Instant.EPOCH;

    protected AutomationVaultKeyPackageEntity() {}

    private AutomationVaultKeyPackageEntity(@NonNull AutomationVaultKeyPackage keyPackage) {
        id =
                new AutomationVaultKeyPackageEntityId(
                        keyPackage.ownerId(), keyPackage.vaultId(), keyPackage.principalId());
        vaultKeyId = keyPackage.vaultKeyId();
        keyAlgorithm = keyPackage.keyAlgorithm();
        encryptedVaultKey = keyPackage.encryptedVaultKey();
        createdAt = keyPackage.createdAt();
        updatedAt = keyPackage.updatedAt();
    }

    static @NonNull AutomationVaultKeyPackageEntity from(
            @NonNull AutomationVaultKeyPackage keyPackage) {
        return new AutomationVaultKeyPackageEntity(keyPackage);
    }

    @NonNull AutomationVaultKeyPackage toStored() {
        return new AutomationVaultKeyPackage(
                id.ownerId,
                id.vaultId,
                id.principalId,
                vaultKeyId,
                keyAlgorithm,
                encryptedVaultKey,
                createdAt,
                updatedAt);
    }
}
