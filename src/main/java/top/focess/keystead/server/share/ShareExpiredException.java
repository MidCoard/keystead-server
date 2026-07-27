package top.focess.keystead.server.share;

import org.jspecify.annotations.NonNull;

final class ShareExpiredException extends RuntimeException {

    ShareExpiredException(@NonNull String message) {
        super(message);
    }
}
