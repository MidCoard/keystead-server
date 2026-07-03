package top.focess.keystead.server.identity;

import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
final class DeviceNotFoundException extends RuntimeException {

    DeviceNotFoundException(@NonNull String message) {
        super(message);
    }
}
