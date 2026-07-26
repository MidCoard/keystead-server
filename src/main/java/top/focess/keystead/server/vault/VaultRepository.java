package top.focess.keystead.server.vault;

import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface VaultRepository extends JpaRepository<VaultEntity, VaultEntityId>, VaultRepositoryWrites {

    default @NonNull Optional<StoredVault> find(
            @NonNull String ownerId, @NonNull String fingerprint) {
        return findById(new VaultEntityId(ownerId, fingerprint)).map(VaultEntity::toStored);
    }

    @Query("select v from VaultEntity v where v.id.fingerprint = :fingerprint")
    @NonNull Optional<VaultEntity> findEntityByFingerprint(
            @Param("fingerprint") @NonNull String fingerprint);

    default @NonNull Optional<StoredVault> findGlobally(@NonNull String fingerprint) {
        return findEntityByFingerprint(fingerprint).map(VaultEntity::toStored);
    }

    default boolean exists(@NonNull String ownerId, @NonNull String fingerprint) {
        return existsById(new VaultEntityId(ownerId, fingerprint));
    }

    @Query("select count(v) from VaultEntity v where v.id.fingerprint = :fingerprint")
    long countByFingerprint(@Param("fingerprint") @NonNull String fingerprint);

    default boolean existsGlobally(@NonNull String fingerprint) {
        return countByFingerprint(fingerprint) > 0;
    }

    @Query("select v from VaultEntity v where v.id.ownerId = :ownerId order by v.id.fingerprint")
    @NonNull List<VaultEntity> listEntities(@Param("ownerId") @NonNull String ownerId);

    default @NonNull List<StoredVault> list(@NonNull String ownerId) {
        return listEntities(ownerId).stream().map(VaultEntity::toStored).toList();
    }
}
