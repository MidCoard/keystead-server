package top.focess.keystead.server.identity;

import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
final class DeviceAlreadyExistsException extends RuntimeException {

    DeviceAlreadyExistsException(@NonNull String message) {
        super(message);
    }
}
