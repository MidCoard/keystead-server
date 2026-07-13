package top.focess.keystead.server.vault;

import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface VaultRotationPackageRepository
        extends JpaRepository<VaultRotationPackageEntity, VaultRotationPackageEntity.Key> {

    @NonNull List<VaultRotationPackageEntity> findByGenerationIdOrderByTargetId(
            @NonNull String generationId);

    long countByGenerationId(@NonNull String generationId);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from VaultRotationPackageEntity p where p.generationId = :generationId")
    int deleteForGeneration(@Param("generationId") @NonNull String generationId);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
            "delete from VaultRotationPackageEntity p where p.generationId = :generationId and p.targetId = :targetId")
    int deleteForTarget(
            @Param("generationId") @NonNull String generationId,
            @Param("targetId") @NonNull String targetId);
}
