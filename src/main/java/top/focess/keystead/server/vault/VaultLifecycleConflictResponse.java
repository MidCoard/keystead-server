package top.focess.keystead.server.vault;

import org.jspecify.annotations.NonNull;

public record VaultLifecycleConflictResponse(@NonNull VaultKeyLifecycleState lifecycleState) {

    public static @NonNull VaultLifecycleConflictResponse from(
            @NonNull VaultLifecycleConflictException exception) {
        return new VaultLifecycleConflictResponse(exception.lifecycleState());
    }
}
