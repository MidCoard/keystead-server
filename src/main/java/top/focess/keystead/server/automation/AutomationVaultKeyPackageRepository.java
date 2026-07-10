package top.focess.keystead.server.automation;

import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;

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
}
