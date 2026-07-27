package top.focess.keystead.server.share;

import org.jspecify.annotations.NonNull;

final class InvalidShareRequestException extends RuntimeException {

    InvalidShareRequestException(@NonNull String message) {
        super(message);
    }
}
