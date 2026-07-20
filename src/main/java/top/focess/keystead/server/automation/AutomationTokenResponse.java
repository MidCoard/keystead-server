package top.focess.keystead.server.automation;

import java.time.Instant;
import java.util.Set;
import org.jspecify.annotations.NonNull;

record AutomationTokenResponse(
        @NonNull String token,
        @NonNull String tokenId,
        @NonNull String principalId,
        @NonNull String vaultId,
        @NonNull Set<AutomationScope> scopes,
        @NonNull Instant expiresAt) {}
