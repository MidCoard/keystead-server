package top.focess.keystead.server.automation;

import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface AutomationVaultKeyPackageRepository
        extends JpaRepository<AutomationVaultKeyPackageEntity, AutomationVaultKeyPackageEntityId> {

    default @NonNull Optional<AutomationVaultKeyPackage> find(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String principalId) {
        return findById(new AutomationVaultKeyPackageEntityId(ownerId, vaultId, principalId))
                .map(AutomationVaultKeyPackageEntity::toStored);
    }

    default void persist(@NonNull AutomationVaultKeyPackage keyPackage) {
        save(AutomationVaultKeyPackageEntity.from(keyPackage));
    }

    @Modifying
    @Query(
            """
            delete from AutomationVaultKeyPackageEntity k
             where k.id.ownerId = :ownerId
               and k.id.principalId = :principalId
            """)
    int deleteForPrincipal(
            @Param("ownerId") @NonNull String ownerId,
            @Param("principalId") @NonNull String principalId);

    @Query(
            """
            select k.id.vaultId from AutomationVaultKeyPackageEntity k
              join VaultKeyStateEntity s
                on s.id.ownerId = k.id.ownerId
               and s.id.vaultId = k.id.vaultId
               and s.currentVaultKeyId = k.vaultKeyId
             where k.id.ownerId = :ownerId
               and k.id.principalId = :principalId
             order by k.id.vaultId
            """)
    @NonNull List<String> listCurrentVaultIds(
            @Param("ownerId") @NonNull String ownerId,
            @Param("principalId") @NonNull String principalId);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
            """
            delete from AutomationVaultKeyPackageEntity k
             where k.id.ownerId = :ownerId
               and k.id.vaultId = :vaultId
            """)
    int deleteForVault(
            @Param("ownerId") @NonNull String ownerId, @Param("vaultId") @NonNull String vaultId);
}
