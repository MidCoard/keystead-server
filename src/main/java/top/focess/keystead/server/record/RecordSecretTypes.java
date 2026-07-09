package top.focess.keystead.server.record;

import java.util.Set;
import org.jspecify.annotations.NonNull;

final class RecordSecretTypes {

    private static final Set<String> ALLOWED =
            Set.of(
                    "LOGIN_PASSWORD",
                    "SECURE_NOTE",
                    "SSH_KEY",
                    "API_TOKEN",
                    "GPG_KEY",
                    "MFA_SECRET",
                    "CERTIFICATE",
                    "GENERIC_SECRET");

    private RecordSecretTypes() {}

    static boolean isSupported(@NonNull String secretType) {
        return ALLOWED.contains(secretType);
    }
}
