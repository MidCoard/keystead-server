package top.focess.keystead.server.share;

import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;

interface ShareRepository extends JpaRepository<ShareEntity, String> {

    default @NonNull Optional<Share> find(@NonNull String code) {
        return findById(code).map(ShareEntity::toStored);
    }

    default void persist(@NonNull Share share) {
        save(ShareEntity.from(share));
    }

    default void remove(@NonNull Share share) {
        delete(ShareEntity.from(share));
    }

    default @NonNull List<Share> listByOwner(@NonNull String ownerId) {
        return findByOwnerIdOrderByCreatedAtDesc(ownerId).stream()
                .map(ShareEntity::toStored)
                .toList();
    }

    List<ShareEntity> findByOwnerIdOrderByCreatedAtDesc(@NonNull String ownerId);
}
