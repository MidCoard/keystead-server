package top.focess.keystead.server.automation;

import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;

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
}
