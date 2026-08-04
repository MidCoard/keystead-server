package top.focess.keystead.server.vaultaccess;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
final class InvalidVaultAccessRequestException extends RuntimeException {

    InvalidVaultAccessRequestException(String message) {
        super(message);
    }
}
