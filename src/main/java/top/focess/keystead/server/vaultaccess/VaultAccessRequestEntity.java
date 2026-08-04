package top.focess.keystead.server.vaultaccess;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

@Entity
@Table(name = "vault_access_requests")
public class VaultAccessRequestEntity {

    @Id
    @Column(name = "request_id", nullable = false)
    @NonNull String requestId = "";

    @Column(name = "username", nullable = false)
    @NonNull String username = "";

    @Column(name = "server_origin", nullable = false, length = 2048)
    @NonNull String serverOrigin = "";

    @Column(name = "fingerprint", nullable = false)
    @NonNull String fingerprint = "";

    @Column(name = "key_algorithm", nullable = false)
    @NonNull String keyAlgorithm = "";

    @Column(name = "exchange_public_key", nullable = false, columnDefinition = "text")
    @NonNull String exchangePublicKey = "";

    @Enumerated(EnumType.STRING)
    @Column(name = "state", nullable = false)
    @NonNull VaultAccessRequestState state = VaultAccessRequestState.PENDING;

    @Column(name = "expires_at", nullable = false)
    @NonNull Instant expiresAt = Instant.EPOCH;

    @Column(name = "vault_fingerprint")
    @Nullable String vaultFingerprint;

    @Column(name = "vault_key_id")
    @Nullable String vaultKeyId;

    @Column(name = "package_key_algorithm")
    @Nullable String packageKeyAlgorithm;

    @Column(name = "encrypted_vault_key", columnDefinition = "text")
    @Nullable String encryptedVaultKey;

    @Column(name = "approved_at")
    @Nullable Instant approvedAt;

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;

    protected VaultAccessRequestEntity() {}
}
