package top.focess.keystead.server.identity;

import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
final class InvalidDeviceProofRequestException extends RuntimeException {

    InvalidDeviceProofRequestException(@NonNull String message) {
        super(message);
    }
}
