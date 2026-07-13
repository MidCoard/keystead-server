package top.focess.keystead.server.recovery;

import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface RecoveryVaultPackageRepository
        extends JpaRepository<RecoveryVaultPackageEntity, RecoveryVaultPackageId> {

    @Query(
            """
            select p from RecoveryVaultPackageEntity p
             where p.id.username = :username
               and p.id.enrollmentId = :enrollmentId
               and p.id.generation = :generation
             order by p.id.vaultId
            """)
    @NonNull List<RecoveryVaultPackageEntity> listForEnrollment(
            @Param("username") @NonNull String username,
            @Param("enrollmentId") @NonNull String enrollmentId,
            @Param("generation") long generation);
}
