package top.focess.keystead.server.record;

import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
final class InvalidRecordRequestException extends RuntimeException {

    InvalidRecordRequestException(@NonNull String message) {
        super(message);
    }
}
