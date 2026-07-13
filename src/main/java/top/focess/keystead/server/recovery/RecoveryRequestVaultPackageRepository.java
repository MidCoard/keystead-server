package top.focess.keystead.server.recovery;

import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface RecoveryRequestVaultPackageRepository
        extends JpaRepository<RecoveryRequestVaultPackageEntity, RecoveryRequestVaultPackageId> {

    @Query(
            """
            select p from RecoveryRequestVaultPackageEntity p
             where p.id.requestId = :requestId
             order by p.id.vaultId
            """)
    @NonNull List<RecoveryRequestVaultPackageEntity> listForRequest(
            @Param("requestId") @NonNull String requestId);
}
