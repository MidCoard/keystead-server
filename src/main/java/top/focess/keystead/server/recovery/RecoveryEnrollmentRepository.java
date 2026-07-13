package top.focess.keystead.server.recovery;

import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.data.jpa.repository.JpaRepository;
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
}
