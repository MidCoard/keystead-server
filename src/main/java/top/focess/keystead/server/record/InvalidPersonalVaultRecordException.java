package top.focess.keystead.server.record;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
final class InvalidPersonalVaultRecordException extends RuntimeException {

    InvalidPersonalVaultRecordException(String message) {
        super(message);
    }
}
