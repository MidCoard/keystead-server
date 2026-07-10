package top.focess.keystead.server.vault;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;

@Entity
@Table(
        name = "vault_key_packages",
        indexes =
                @Index(
                        name = "idx_vault_key_packages_owner_vault",
                        columnList = "owner_id, vault_id"))
public class VaultKeyPackageEntity {

    @EmbeddedId @NonNull VaultKeyPackageEntityId id = new VaultKeyPackageEntityId();

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

    protected VaultKeyPackageEntity() {}

    private VaultKeyPackageEntity(@NonNull StoredVaultKeyPackage keyPackage) {
        this.id =
                new VaultKeyPackageEntityId(
                        keyPackage.ownerId(), keyPackage.vaultId(), keyPackage.deviceId());
        this.vaultKeyId = keyPackage.vaultKeyId();
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
                vaultKeyId,
                keyAlgorithm,
                encryptedVaultKey,
                createdAt,
                updatedAt);
    }
}
