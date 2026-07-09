package top.focess.keystead.server.identity;

import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
final class InvalidDeviceRegistrationRequestException extends RuntimeException {

    InvalidDeviceRegistrationRequestException(@NonNull String message) {
        super(message);
    }
}
