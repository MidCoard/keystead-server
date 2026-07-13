package top.focess.keystead.server.recovery;

import java.time.Instant;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface RecoverySessionRepository extends JpaRepository<RecoverySessionEntity, String> {

    @Query(
            """
            select s from RecoverySessionEntity s
             where s.tokenHash = :tokenHash
               and s.consumedAt is null
               and s.expiresAt > :now
            """)
    @NonNull Optional<RecoverySessionEntity> findActive(
            @Param("tokenHash") @NonNull String tokenHash, @Param("now") @NonNull Instant now);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
            """
            update RecoverySessionEntity s
               set s.consumedAt = :now
             where s.tokenHash = :tokenHash
               and s.consumedAt is null
               and s.expiresAt > :now
            """)
    int consumeActive(
            @Param("tokenHash") @NonNull String tokenHash, @Param("now") @NonNull Instant now);
}
