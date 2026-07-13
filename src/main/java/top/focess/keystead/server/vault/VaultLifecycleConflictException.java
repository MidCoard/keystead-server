package top.focess.keystead.server.vault;

import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public final class VaultLifecycleConflictException extends RuntimeException {

    private final VaultKeyLifecycleState lifecycleState;

    VaultLifecycleConflictException(@NonNull VaultKeyLifecycleState lifecycleState) {
        super("Vault key lifecycle blocks writes: " + lifecycleState);
        this.lifecycleState = lifecycleState;
    }

    public @NonNull VaultKeyLifecycleState lifecycleState() {
        return lifecycleState;
    }
}
