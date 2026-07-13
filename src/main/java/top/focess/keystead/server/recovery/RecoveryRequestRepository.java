package top.focess.keystead.server.recovery;

import java.time.Instant;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface RecoveryRequestRepository extends JpaRepository<RecoveryRequestEntity, String> {

    @Query(
            """
            select r from RecoveryRequestEntity r
             where r.username = :username
               and r.state = top.focess.keystead.server.recovery.RecoveryRequestState.PENDING
               and r.expiresAt > :now
             order by r.createdAt, r.requestId
            """)
    @NonNull List<RecoveryRequestEntity> listPending(
            @Param("username") @NonNull String username, @Param("now") @NonNull Instant now);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
            """
            update RecoveryRequestEntity r
               set r.state = top.focess.keystead.server.recovery.RecoveryRequestState.APPROVED,
                   r.approvedByDeviceId = :deviceId,
                   r.approvedAt = :now
             where r.requestId = :requestId
               and r.username = :username
               and r.state = top.focess.keystead.server.recovery.RecoveryRequestState.PENDING
               and r.expiresAt > :now
            """)
    int approvePending(
            @Param("requestId") @NonNull String requestId,
            @Param("username") @NonNull String username,
            @Param("deviceId") @NonNull String deviceId,
            @Param("now") @NonNull Instant now);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
            """
            update RecoveryRequestEntity r
               set r.state = top.focess.keystead.server.recovery.RecoveryRequestState.CONSUMED,
                   r.consumedAt = :now
             where r.requestId = :requestId
               and r.state = top.focess.keystead.server.recovery.RecoveryRequestState.APPROVED
               and r.expiresAt > :now
            """)
    int consumeApproved(
            @Param("requestId") @NonNull String requestId, @Param("now") @NonNull Instant now);
}
