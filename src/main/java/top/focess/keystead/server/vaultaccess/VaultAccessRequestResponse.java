package top.focess.keystead.server.vaultaccess;

import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public record VaultAccessRequestResponse(
        @NonNull String requestId,
        @NonNull String accountId,
        @NonNull String serverOrigin,
        @NonNull String fingerprint,
        @NonNull String keyAlgorithm,
        @NonNull String exchangePublicKey,
        @NonNull VaultAccessRequestState state,
        @NonNull Instant expiresAt,
        @NonNull String canonicalRequest,
        @Nullable VaultAccessApprovedPackageResponse approvedPackage,
        @Nullable Instant approvedAt) {

    @Override
    public @NonNull String toString() {
        return "VaultAccessRequestResponse[requestId=%s, accountId=%s, serverOrigin=%s, fingerprint=%s, keyAlgorithm=%s, exchangePublicKey=[REDACTED], state=%s, expiresAt=%s, canonicalRequest=[REDACTED], approvedPackage=%s, approvedAt=%s]"
                .formatted(
                        requestId,
                        accountId,
                        serverOrigin,
                        fingerprint,
                        keyAlgorithm,
                        state,
                        expiresAt,
                        approvedPackage,
                        approvedAt);
    }
}
