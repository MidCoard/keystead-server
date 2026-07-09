package top.focess.keystead.server.vault;

import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
final class InvalidVaultRequestException extends RuntimeException {

    InvalidVaultRequestException(@NonNull String message) {
        super(message);
    }
}
