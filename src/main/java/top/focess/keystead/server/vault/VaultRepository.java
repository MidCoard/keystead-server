package top.focess.keystead.server.vault;

import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface VaultRepository extends JpaRepository<VaultEntity, VaultEntityId>, VaultRepositoryWrites {

    default @NonNull Optional<StoredVault> find(@NonNull String ownerId, @NonNull String vaultId) {
        return findById(new VaultEntityId(ownerId, vaultId)).map(VaultEntity::toStored);
    }

    @Query("select v from VaultEntity v where v.id.vaultId = :vaultId")
    @NonNull Optional<VaultEntity> findEntityByVaultId(@Param("vaultId") @NonNull String vaultId);

    default @NonNull Optional<StoredVault> findGlobally(@NonNull String vaultId) {
        return findEntityByVaultId(vaultId).map(VaultEntity::toStored);
    }

    default boolean exists(@NonNull String ownerId, @NonNull String vaultId) {
        return existsById(new VaultEntityId(ownerId, vaultId));
    }

    @Query("select count(v) from VaultEntity v where v.id.vaultId = :vaultId")
    long countByVaultId(@Param("vaultId") @NonNull String vaultId);

    default boolean existsGlobally(@NonNull String vaultId) {
        return countByVaultId(vaultId) > 0;
    }

    @Query("select v from VaultEntity v where v.id.ownerId = :ownerId order by v.id.vaultId")
    @NonNull List<VaultEntity> listEntities(@Param("ownerId") @NonNull String ownerId);

    default @NonNull List<StoredVault> list(@NonNull String ownerId) {
        return listEntities(ownerId).stream().map(VaultEntity::toStored).toList();
    }
}
