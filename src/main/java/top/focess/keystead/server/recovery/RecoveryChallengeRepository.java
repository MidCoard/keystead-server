package top.focess.keystead.server.recovery;

import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

interface RecoveryChallengeRepository extends JpaRepository<RecoveryChallengeEntity, String> {

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    @Query(
            """
            update RecoveryChallengeEntity c
               set c.attempts = c.attempts + 1
             where c.challengeId = :challengeId
               and c.consumedAt is null
               and c.expiresAt > :now
               and c.attempts < :maximumAttempts
            """)
    int claimAttempt(
            @Param("challengeId") @NonNull String challengeId,
            @Param("now") @NonNull Instant now,
            @Param("maximumAttempts") int maximumAttempts);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
            """
            update RecoveryChallengeEntity c
               set c.consumedAt = :now
             where c.challengeId = :challengeId
               and c.consumedAt is null
               and c.expiresAt > :now
            """)
    int consumeActive(
            @Param("challengeId") @NonNull String challengeId, @Param("now") @NonNull Instant now);
}
