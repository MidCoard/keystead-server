package top.focess.keystead.server.vaultaccess;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
final class VaultAccessDeniedException extends RuntimeException {

    VaultAccessDeniedException() {
        super("Vault access approval failed");
    }
}
