package top.focess.keystead.server.automation;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

@Entity
@Table(name = "automation_tokens")
public class AutomationTokenEntity {

    @Id
    @Column(name = "token_hash", nullable = false)
    @NonNull String tokenHash = "";

    @Column(name = "owner_id", nullable = false)
    @NonNull String ownerId = "";

    @Column(name = "principal_id", nullable = false)
    @NonNull String principalId = "";

    @Column(name = "vault_id", nullable = false)
    @NonNull String vaultId = "";

    @Column(name = "scopes", nullable = false)
    @NonNull String scopes = "";

    @Column(name = "token_id", nullable = false, unique = true)
    @NonNull String tokenId = "";

    @Column(name = "granted_secret_ids", nullable = false)
    @NonNull String grantedSecretIds = "";

    @Column(name = "expires_at", nullable = false)
    @NonNull Instant expiresAt = Instant.EPOCH;

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;

    @Column(name = "revoked_at")
    @Nullable Instant revokedAt;

    @Column(name = "last_used_at")
    @Nullable Instant lastUsedAt;

    protected AutomationTokenEntity() {}

    private AutomationTokenEntity(@NonNull AutomationToken token) {
        tokenHash = token.tokenHash();
        ownerId = token.ownerId();
        principalId = token.principalId();
        vaultId = token.vaultId();
        scopes = token.scopes();
        tokenId = token.tokenId();
        grantedSecretIds = token.grantedSecretIds();
        expiresAt = token.expiresAt();
        createdAt = token.createdAt();
        revokedAt = token.revokedAt();
        lastUsedAt = token.lastUsedAt();
    }

    static @NonNull AutomationTokenEntity from(@NonNull AutomationToken token) {
        return new AutomationTokenEntity(token);
    }

    @NonNull AutomationToken toStored() {
        return new AutomationToken(
                tokenHash,
                ownerId,
                principalId,
                vaultId,
                scopes,
                expiresAt,
                createdAt,
                revokedAt,
                lastUsedAt,
                tokenId,
                grantedSecretIds);
    }
}
