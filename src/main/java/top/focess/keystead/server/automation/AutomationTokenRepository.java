package top.focess.keystead.server.automation;

import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;

interface AutomationTokenRepository extends JpaRepository<AutomationTokenEntity, String> {

    default @NonNull Optional<AutomationToken> find(@NonNull String tokenHash) {
        return findById(tokenHash).map(AutomationTokenEntity::toStored);
    }

    default void persist(@NonNull AutomationToken token) {
        save(AutomationTokenEntity.from(token));
    }
}
