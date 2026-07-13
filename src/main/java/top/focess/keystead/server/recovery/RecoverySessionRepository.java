package top.focess.keystead.server.recovery;

import java.time.Instant;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
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
}
