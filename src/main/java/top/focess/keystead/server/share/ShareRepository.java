package top.focess.keystead.server.share;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface ShareRepository extends JpaRepository<ShareEntity, String> {

    default @NonNull Optional<Share> find(@NonNull String code) {
        return findById(code).map(ShareEntity::toStored);
    }

    default void persist(@NonNull Share share) {
        save(ShareEntity.from(share));
    }

    default @NonNull List<Share> listByOwner(@NonNull String ownerId) {
        return findByOwnerIdOrderByCreatedAtDesc(ownerId).stream()
                .map(ShareEntity::toStored)
                .toList();
    }

    List<ShareEntity> findByOwnerIdOrderByCreatedAtDesc(@NonNull String ownerId);

    /**
     * Atomically deletes the share with the given code, returning the number of rows affected. Used
     * for burn-after-reading and expired-share purges so that two concurrent redeems cannot both
     * observe and return the payload: only the transaction that actually deletes the row wins.
     */
    @Modifying
    @Query("delete from ShareEntity s where s.code = :code")
    int deleteByCode(@Param("code") @NonNull String code);

    /**
     * Atomically deletes the share with the given code only if it belongs to {@code ownerId},
     * returning the number of rows affected. Hides existence from non-owners (they get 0, identical
     * to a missing code) and avoids a separate read-then-delete window.
     */
    @Modifying
    @Query("delete from ShareEntity s where s.code = :code and s.ownerId = :ownerId")
    int deleteByCodeAndOwner(
            @Param("code") @NonNull String code, @Param("ownerId") @NonNull String ownerId);

    /**
     * Bulk-deletes every share whose expiry has passed; backed by {@code idx_shares_expires_at}.
     */
    @Modifying
    @Query("delete from ShareEntity s where s.expiresAt < :now")
    int deleteExpired(@Param("now") @NonNull Instant now);
}
