package top.focess.keystead.server.share;

import org.jspecify.annotations.NonNull;

final class ShareNotFoundException extends RuntimeException {

    ShareNotFoundException(@NonNull String message) {
        super(message);
    }
}
