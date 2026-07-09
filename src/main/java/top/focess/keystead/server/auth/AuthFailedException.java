package top.focess.keystead.server.auth;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

final class AuthFailedException extends RuntimeException {

    AuthFailedException(@NonNull String message) {
        super(message);
    }

    AuthFailedException(@NonNull String message, @Nullable Throwable cause) {
        super(message, cause);
    }
}
