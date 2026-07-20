package top.focess.keystead.server.automation;

import java.time.Instant;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Owner-facing view of an automation token. Unlike {@link AutomationTokenResponse} the raw bearer
 * value is never present: this is used for listing and management after the one-time issuance.
 */
record AutomationTokenSummary(
        @NonNull String tokenId,
        @NonNull String principalId,
        @NonNull Set<AutomationScope> scopes,
        @NonNull Set<String> grantedSecretIds,
        @NonNull Instant expiresAt,
        @NonNull Instant createdAt,
        @Nullable Instant revokedAt,
        @Nullable Instant lastUsedAt) {}
