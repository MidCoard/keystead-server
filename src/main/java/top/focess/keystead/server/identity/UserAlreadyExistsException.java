package top.focess.keystead.server.identity;

import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
final class UserAlreadyExistsException extends RuntimeException {

    UserAlreadyExistsException(@NonNull String message) {
        super(message);
    }
}
