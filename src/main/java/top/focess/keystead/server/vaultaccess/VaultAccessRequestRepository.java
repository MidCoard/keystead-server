package top.focess.keystead.server.vaultaccess;

import java.time.Instant;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface VaultAccessRequestRepository extends JpaRepository<VaultAccessRequestEntity, String> {

    @Query(
            """
            select r from VaultAccessRequestEntity r
             where r.username = :username
               and r.state = top.focess.keystead.server.vaultaccess.VaultAccessRequestState.PENDING
               and r.expiresAt > :now
             order by r.createdAt, r.requestId
            """)
    @NonNull List<VaultAccessRequestEntity> listPending(
            @Param("username") @NonNull String username, @Param("now") @NonNull Instant now);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
            """
            update VaultAccessRequestEntity r
               set r.state = top.focess.keystead.server.vaultaccess.VaultAccessRequestState.APPROVED,
                   r.vaultFingerprint = :vaultFingerprint,
                   r.vaultKeyId = :vaultKeyId,
                   r.packageKeyAlgorithm = :keyAlgorithm,
                   r.encryptedVaultKey = :encryptedVaultKey,
                   r.approvedAt = :now
             where r.requestId = :requestId
               and r.username = :username
               and r.state = top.focess.keystead.server.vaultaccess.VaultAccessRequestState.PENDING
               and r.expiresAt > :now
            """)
    int approvePending(
            @Param("requestId") @NonNull String requestId,
            @Param("username") @NonNull String username,
            @Param("vaultFingerprint") @NonNull String vaultFingerprint,
            @Param("vaultKeyId") @NonNull String vaultKeyId,
            @Param("keyAlgorithm") @NonNull String keyAlgorithm,
            @Param("encryptedVaultKey") @NonNull String encryptedVaultKey,
            @Param("now") @NonNull Instant now);
}
