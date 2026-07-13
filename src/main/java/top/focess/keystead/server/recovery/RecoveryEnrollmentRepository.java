package top.focess.keystead.server.recovery;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface RecoveryEnrollmentRepository
        extends JpaRepository<RecoveryEnrollmentEntity, RecoveryEnrollmentId> {

    @Query(
            """
            select e from RecoveryEnrollmentEntity e
             where e.id.username = :username
               and e.state in (top.focess.keystead.server.recovery.RecoveryEnrollmentState.PENDING,
                               top.focess.keystead.server.recovery.RecoveryEnrollmentState.ACTIVE)
             order by e.id.generation
            """)
    @NonNull List<RecoveryEnrollmentEntity> listCurrent(
            @Param("username") @NonNull String username);

    @Query(
            """
            select e from RecoveryEnrollmentEntity e
             where e.id.username = :username
               and e.state = top.focess.keystead.server.recovery.RecoveryEnrollmentState.PENDING
            """)
    @NonNull Optional<RecoveryEnrollmentEntity> findPending(
            @Param("username") @NonNull String username);

    @Query(
            """
            select e from RecoveryEnrollmentEntity e
             where e.id.username = :username
               and e.state = top.focess.keystead.server.recovery.RecoveryEnrollmentState.ACTIVE
            """)
    @NonNull Optional<RecoveryEnrollmentEntity> findActive(
            @Param("username") @NonNull String username);

    @NonNull Optional<RecoveryEnrollmentEntity> findByIdUsernameAndIdEnrollmentId(
            @NonNull String username, @NonNull String enrollmentId);

    @Query(
            """
            select max(e.id.generation) from RecoveryEnrollmentEntity e
             where e.id.username = :username
            """)
    @Nullable Long maximumGeneration(@Param("username") @NonNull String username);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
            """
            update RecoveryEnrollmentEntity e
               set e.state = top.focess.keystead.server.recovery.RecoveryEnrollmentState.CONSUMED,
                   e.lifecycleMarker = null,
                   e.consumedAt = :now
             where e.id.username = :username
               and e.id.enrollmentId = :enrollmentId
               and e.id.generation = :generation
               and e.state = top.focess.keystead.server.recovery.RecoveryEnrollmentState.ACTIVE
            """)
    int consumeActive(
            @Param("username") @NonNull String username,
            @Param("enrollmentId") @NonNull String enrollmentId,
            @Param("generation") long generation,
            @Param("now") @NonNull Instant now);

    @Query(
            """
            select e from RecoveryEnrollmentEntity e
              join RecoveryVaultPackageEntity p
                on p.id.username = e.id.username
               and p.id.enrollmentId = e.id.enrollmentId
               and p.id.generation = e.id.generation
             where e.id.username = :username
               and e.state = top.focess.keystead.server.recovery.RecoveryEnrollmentState.ACTIVE
               and p.id.vaultId = :vaultId
               and p.vaultKeyId = :currentVaultKeyId
             order by e.id.enrollmentId, e.id.generation
            """)
    @NonNull List<RecoveryEnrollmentEntity> listRotationTargets(
            @Param("username") @NonNull String username,
            @Param("vaultId") @NonNull String vaultId,
            @Param("currentVaultKeyId") @NonNull String currentVaultKeyId);
}
