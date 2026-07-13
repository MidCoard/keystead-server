package top.focess.keystead.server.automation;

import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface AutomationPrincipalRepository
        extends JpaRepository<AutomationPrincipalEntity, AutomationPrincipalEntityId> {

    default @NonNull Optional<AutomationPrincipal> find(
            @NonNull String ownerId, @NonNull String principalId) {
        return findById(new AutomationPrincipalEntityId(ownerId, principalId))
                .map(AutomationPrincipalEntity::toStored);
    }

    default void persist(@NonNull AutomationPrincipal principal) {
        save(AutomationPrincipalEntity.from(principal));
    }

    @Query(
            """
            select p from AutomationPrincipalEntity p
              join AutomationVaultKeyPackageEntity k
                on k.id.ownerId = p.id.ownerId
               and k.id.principalId = p.id.principalId
             where p.id.ownerId = :ownerId
               and p.revokedAt is null
               and k.id.vaultId = :vaultId
               and k.vaultKeyId = :currentVaultKeyId
             order by p.id.principalId
            """)
    @NonNull List<AutomationPrincipalEntity> listRotationTargets(
            @Param("ownerId") @NonNull String ownerId,
            @Param("vaultId") @NonNull String vaultId,
            @Param("currentVaultKeyId") @NonNull String currentVaultKeyId);
}
