package top.focess.keystead.server.identity;

import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;

interface UserRepository extends JpaRepository<UserEntity, String> {

    default @NonNull Optional<StoredUser> find(@NonNull String username) {
        return findById(username).map(UserEntity::toStored);
    }

    default boolean exists(@NonNull String username) {
        return existsById(username);
    }

    default void insert(@NonNull StoredUser user) {
        save(UserEntity.from(user));
    }
}
