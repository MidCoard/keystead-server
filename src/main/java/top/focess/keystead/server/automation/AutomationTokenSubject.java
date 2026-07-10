package top.focess.keystead.server.automation;

import java.util.Set;
import org.jspecify.annotations.NonNull;

public record AutomationTokenSubject(
        @NonNull String ownerId,
        @NonNull String principalId,
        @NonNull String vaultId,
        @NonNull Set<AutomationScope> scopes) {

    public boolean hasScope(@NonNull AutomationScope scope) {
        return scopes.contains(scope);
    }
}
