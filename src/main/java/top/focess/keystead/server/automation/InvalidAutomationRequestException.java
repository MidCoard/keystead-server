package top.focess.keystead.server.automation;

import org.jspecify.annotations.NonNull;

final class InvalidAutomationRequestException extends RuntimeException {

    InvalidAutomationRequestException(@NonNull String message) {
        super(message);
    }
}
