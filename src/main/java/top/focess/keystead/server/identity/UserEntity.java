package top.focess.keystead.server.identity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;

@Entity
@Table(name = "app_users")
public class UserEntity {

    @Id
    @Column(name = "username", nullable = false)
    @NonNull String username = "";

    @Column(name = "password_hash", nullable = false)
    @NonNull String passwordHash = "";

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;

    @Column(name = "updated_at", nullable = false)
    @NonNull Instant updatedAt = Instant.EPOCH;

    @Column(name = "token_version", nullable = false)
    long tokenVersion;

    protected UserEntity() {}

    UserEntity(
            @NonNull String username,
            @NonNull String passwordHash,
            @NonNull Instant createdAt,
            @NonNull Instant updatedAt,
            long tokenVersion) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
        this.tokenVersion = tokenVersion;
    }

    static @NonNull UserEntity from(@NonNull StoredUser user) {
        return new UserEntity(
                user.username(),
                user.passwordHash(),
                user.createdAt(),
                user.updatedAt(),
                user.tokenVersion());
    }

    @NonNull StoredUser toStored() {
        return new StoredUser(username, passwordHash, createdAt, updatedAt, tokenVersion);
    }
}
