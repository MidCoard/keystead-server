package top.focess.keystead.server.vault;

import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface VaultRotationTargetRepository
        extends JpaRepository<VaultRotationTargetEntity, VaultRotationTargetEntity.Key> {

    @NonNull List<VaultRotationTargetEntity> findByGenerationIdOrderByTargetId(
            @NonNull String generationId);

    long countByGenerationId(@NonNull String generationId);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from VaultRotationTargetEntity t where t.generationId = :generationId")
    int deleteForGeneration(@Param("generationId") @NonNull String generationId);
}
