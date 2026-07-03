package top.focess.keystead.server.vault;

import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
final class VaultNotFoundException extends RuntimeException {

    VaultNotFoundException(@NonNull String message) {
        super(message);
    }

    VaultNotFoundException(@NonNull String message, @NonNull Throwable cause) {
        super(message, cause);
    }
}
