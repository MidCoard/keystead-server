package top.focess.keystead.server.vault;

import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;

interface VaultKeyRotationRepository extends JpaRepository<VaultKeyRotationEntity, VaultEntityId> {
    default @NonNull Optional<VaultKeyRotation> find(
            @NonNull String ownerId, @NonNull String vaultId) {
        return findById(new VaultEntityId(ownerId, vaultId)).map(VaultKeyRotationEntity::toStored);
    }

    default void persist(@NonNull VaultKeyRotation value) {
        save(VaultKeyRotationEntity.from(value));
    }
}
