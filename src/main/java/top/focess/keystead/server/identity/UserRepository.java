package top.focess.keystead.server.identity;

import java.time.Instant;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<UserEntity, String>, UserRepositoryWrites {

    default @NonNull Optional<StoredUser> find(@NonNull String username) {
        return findById(username).map(UserEntity::toStored);
    }

    default boolean exists(@NonNull String username) {
        return existsById(username);
    }

    @Modifying
    @Query(
            "update UserEntity u set u.tokenVersion = u.tokenVersion + 1 where u.username = :username")
    void incrementTokenVersion(@Param("username") @NonNull String username);

    @Modifying
    @Query(
            """
            update UserEntity u
               set u.passwordHash = :passwordHash,
                   u.updatedAt = :updatedAt,
                   u.tokenVersion = u.tokenVersion + 1
             where u.username = :username
            """)
    int resetCredentials(
            @Param("username") @NonNull String username,
            @Param("passwordHash") @NonNull String passwordHash,
            @Param("updatedAt") @NonNull Instant updatedAt);
}
