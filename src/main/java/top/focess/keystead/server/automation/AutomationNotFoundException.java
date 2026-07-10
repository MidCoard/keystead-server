package top.focess.keystead.server.automation;

import org.jspecify.annotations.NonNull;

final class AutomationNotFoundException extends RuntimeException {

    AutomationNotFoundException(@NonNull String message) {
        super(message);
    }
}
