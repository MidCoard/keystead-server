package top.focess.keystead.server.identity;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public final class IdentityRecoveryConflictException extends RuntimeException {

    IdentityRecoveryConflictException(String message) {
        super(message);
    }
}
