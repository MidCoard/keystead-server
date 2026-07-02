package top.focess.keystead.server.record;

import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
final class RevisionConflictException extends RuntimeException {

    RevisionConflictException(@NonNull String message) {
        super(message);
    }
}
