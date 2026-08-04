package top.focess.keystead.server.vaultaccess;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
final class VaultAccessRequestNotFoundException extends RuntimeException {

    VaultAccessRequestNotFoundException() {
        super("Vault access request does not exist");
    }
}
