package top.focess.keystead.server.recovery;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
final class RecoveryAuthenticationFailedException extends RuntimeException {

    RecoveryAuthenticationFailedException() {
        super("Recovery failed");
    }
}
