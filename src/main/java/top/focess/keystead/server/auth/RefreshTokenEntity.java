package top.focess.keystead.server.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

@Entity
@Table(name = "auth_refresh_tokens")
public class RefreshTokenEntity {

    @Id
    @Column(name = "token_hash", nullable = false, length = 64)
    @NonNull String tokenHash = "";

    @Column(name = "username", nullable = false)
    @NonNull String username = "";

    @Column(name = "device_id")
    @Nullable String deviceId;

    @Column(name = "refresh_expires_at", nullable = false)
    @NonNull Instant refreshExpiresAt = Instant.EPOCH;

    @Column(name = "revoked_at")
    @Nullable Instant revokedAt;

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;

    @Column(name = "last_used_at", nullable = false)
    @NonNull Instant lastUsedAt = Instant.EPOCH;

    protected RefreshTokenEntity() {}

    private RefreshTokenEntity(@NonNull StoredRefreshToken token) {
        this.tokenHash = token.tokenHash();
        this.username = token.username();
        this.deviceId = token.deviceId();
        this.refreshExpiresAt = token.refreshExpiresAt();
        this.revokedAt = token.revokedAt();
        this.createdAt = token.createdAt();
        this.lastUsedAt = token.lastUsedAt();
    }

    static @NonNull RefreshTokenEntity from(@NonNull StoredRefreshToken token) {
        return new RefreshTokenEntity(token);
    }

    @NonNull StoredRefreshToken toStored() {
        return new StoredRefreshToken(
                tokenHash, username, deviceId, refreshExpiresAt, revokedAt, createdAt, lastUsedAt);
    }
}
