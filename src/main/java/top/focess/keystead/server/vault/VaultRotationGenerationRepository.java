package top.focess.keystead.server.vault;

import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;

interface VaultRotationGenerationRepository
        extends JpaRepository<VaultRotationGenerationEntity, String> {

    @NonNull Optional<VaultRotationGenerationEntity> findByGenerationIdAndOwnerIdAndVaultId(
            @NonNull String generationId, @NonNull String ownerId, @NonNull String vaultId);
}
