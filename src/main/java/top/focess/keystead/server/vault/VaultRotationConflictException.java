package top.focess.keystead.server.vault;

import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
final class VaultRotationConflictException extends RuntimeException {

    VaultRotationConflictException(@NonNull String message) {
        super(message);
    }
}
