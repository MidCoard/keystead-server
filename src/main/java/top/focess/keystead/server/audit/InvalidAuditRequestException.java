package top.focess.keystead.server.audit;

import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
final class InvalidAuditRequestException extends RuntimeException {

    InvalidAuditRequestException(@NonNull String message) {
        super(message);
    }
}
