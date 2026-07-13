package top.focess.keystead.server.recovery;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
final class RecoveryConflictException extends RuntimeException {

    RecoveryConflictException(String message) {
        super(message);
    }
}
