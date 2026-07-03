package top.focess.keystead.server.vault;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;

@Entity
@Table(name = "vault_key_packages")
public class VaultKeyPackageEntity {

    @EmbeddedId @NonNull VaultKeyPackageEntityId id = new VaultKeyPackageEntityId();

    @Column(name = "key_algorithm", nullable = false)
    @NonNull String keyAlgorithm = "";

    @Column(name = "encrypted_vault_key", nullable = false, columnDefinition = "text")
    @NonNull String encryptedVaultKey = "";

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;

    @Column(name = "updated_at", nullable = false)
    @NonNull Instant updatedAt = Instant.EPOCH;

    protected VaultKeyPackageEntity() {}

    private VaultKeyPackageEntity(@NonNull StoredVaultKeyPackage keyPackage) {
        this.id =
                new VaultKeyPackageEntityId(
                        keyPackage.ownerId(), keyPackage.vaultId(), keyPackage.deviceId());
        this.keyAlgorithm = keyPackage.keyAlgorithm();
        this.encryptedVaultKey = keyPackage.encryptedVaultKey();
        this.createdAt = keyPackage.createdAt();
        this.updatedAt = keyPackage.updatedAt();
    }

    static @NonNull VaultKeyPackageEntity from(@NonNull StoredVaultKeyPackage keyPackage) {
        return new VaultKeyPackageEntity(keyPackage);
    }

    @NonNull StoredVaultKeyPackage toStored() {
        return new StoredVaultKeyPackage(
                id.ownerId,
                id.vaultId,
                id.deviceId,
                keyAlgorithm,
                encryptedVaultKey,
                createdAt,
                updatedAt);
    }
}
