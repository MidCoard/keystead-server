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

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
            """
            update VaultKeyStateEntity s
               set s.lifecycleState = top.focess.keystead.server.vault.VaultKeyLifecycleState.ROTATING,
                   s.lifecycleVersion = s.lifecycleVersion + 1,
                   s.pendingGenerationId = :generationId,
                   s.updatedAt = :updatedAt
             where s.id.ownerId = :ownerId
               and s.id.vaultId = :vaultId
               and s.currentVaultKeyId = :expectedCurrentVaultKeyId
               and s.lifecycleVersion = :expectedLifecycleVersion
               and s.pendingGenerationId is null
               and s.lifecycleState in (
                   top.focess.keystead.server.vault.VaultKeyLifecycleState.STABLE,
                   top.focess.keystead.server.vault.VaultKeyLifecycleState.ROTATION_REQUIRED)
            """)
    int beginRotation(
            @Param("ownerId") @NonNull String ownerId,
            @Param("vaultId") @NonNull String vaultId,
            @Param("expectedCurrentVaultKeyId") @NonNull String expectedCurrentVaultKeyId,
            @Param("expectedLifecycleVersion") long expectedLifecycleVersion,
            @Param("generationId") @NonNull String generationId,
            @Param("updatedAt") @NonNull Instant updatedAt);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
            """
            update VaultKeyStateEntity s
               set s.lifecycleState = :priorLifecycleState,
                   s.lifecycleVersion = s.lifecycleVersion + 1,
                   s.pendingGenerationId = null,
                   s.updatedAt = :updatedAt
             where s.id.ownerId = :ownerId
               and s.id.vaultId = :vaultId
               and s.lifecycleState = top.focess.keystead.server.vault.VaultKeyLifecycleState.ROTATING
               and s.lifecycleVersion = :expectedLifecycleVersion
               and s.pendingGenerationId = :generationId
            """)
    int cancelRotation(
            @Param("ownerId") @NonNull String ownerId,
            @Param("vaultId") @NonNull String vaultId,
            @Param("generationId") @NonNull String generationId,
            @Param("expectedLifecycleVersion") long expectedLifecycleVersion,
            @Param("priorLifecycleState") @NonNull VaultKeyLifecycleState priorLifecycleState,
            @Param("updatedAt") @NonNull Instant updatedAt);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
            """
            update VaultKeyStateEntity s
               set s.currentVaultKeyId = :targetVaultKeyId,
                   s.lifecycleState = top.focess.keystead.server.vault.VaultKeyLifecycleState.STABLE,
                   s.lifecycleVersion = s.lifecycleVersion + 1,
                   s.pendingGenerationId = null,
                   s.updatedAt = :updatedAt
             where s.id.ownerId = :ownerId
               and s.id.vaultId = :vaultId
               and s.lifecycleState = top.focess.keystead.server.vault.VaultKeyLifecycleState.ROTATING
               and s.lifecycleVersion = :expectedLifecycleVersion
               and s.pendingGenerationId = :generationId
            """)
    int commitRotation(
            @Param("ownerId") @NonNull String ownerId,
            @Param("vaultId") @NonNull String vaultId,
            @Param("generationId") @NonNull String generationId,
            @Param("expectedLifecycleVersion") long expectedLifecycleVersion,
            @Param("targetVaultKeyId") @NonNull String targetVaultKeyId,
            @Param("updatedAt") @NonNull Instant updatedAt);
}
