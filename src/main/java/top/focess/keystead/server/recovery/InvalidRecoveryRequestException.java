package top.focess.keystead.server.recovery;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
final class InvalidRecoveryRequestException extends RuntimeException {

    InvalidRecoveryRequestException(String message) {
        super(message);
    }
}
