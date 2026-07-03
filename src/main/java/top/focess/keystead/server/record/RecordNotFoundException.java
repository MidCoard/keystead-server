package top.focess.keystead.server.record;

import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
final class RecordNotFoundException extends RuntimeException {

    RecordNotFoundException(@NonNull String message) {
        super(message);
    }
}
