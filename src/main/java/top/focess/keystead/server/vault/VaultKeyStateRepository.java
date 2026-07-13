package top.focess.keystead.server.vault;

import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface VaultKeyStateRepository extends JpaRepository<VaultKeyStateEntity, VaultEntityId> {

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
            """
            update VaultKeyStateEntity s
               set s.lifecycleState = top.focess.keystead.server.vault.VaultKeyLifecycleState.ROTATION_REQUIRED,
                   s.lifecycleVersion = s.lifecycleVersion + 1,
                   s.updatedAt = :updatedAt
             where s.id.ownerId = :ownerId
               and s.id.vaultId = :vaultId
               and s.currentVaultKeyId is not null
               and s.lifecycleState = top.focess.keystead.server.vault.VaultKeyLifecycleState.STABLE
            """)
    int markRotationRequired(
            @Param("ownerId") @NonNull String ownerId,
            @Param("vaultId") @NonNull String vaultId,
            @Param("updatedAt") @NonNull Instant updatedAt);
}
