package top.focess.keystead.server.automation;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotEmpty;
import java.time.Instant;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

record IssueAutomationTokenRequest(
        @NonNull @Future Instant expiresAt,
        @NonNull @NotEmpty Set<AutomationScope> scopes,
        @Nullable Set<String> grantedSecretIds) {}
