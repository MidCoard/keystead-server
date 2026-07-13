package top.focess.keystead.server.recovery;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
final class RecoveryNotFoundException extends RuntimeException {

    RecoveryNotFoundException(String message) {
        super(message);
    }
}
