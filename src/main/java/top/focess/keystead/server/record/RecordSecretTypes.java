package top.focess.keystead.server.record;

import java.util.List;
import java.util.Set;
import org.jspecify.annotations.NonNull;

final class RecordSecretTypes {

    private static final String CATEGORY_COMMUNICATION = "communication";
    private static final String CATEGORY_DEVELOPMENT = "development";

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

    private static final List<SecretTypeCatalogEntryResponse> CATALOG =
            List.of(
                    new SecretTypeCatalogEntryResponse(
                            "LOGIN_PASSWORD",
                            CATEGORY_COMMUNICATION,
                            null,
                            null,
                            false,
                            null,
                            false,
                            List.of(
                                    field("username", "SECRET", true, true),
                                    field("password", "SECRET", true, true),
                                    field("url", "TEXT", false, true),
                                    field("notes", "SECRET", false, true))),
                    new SecretTypeCatalogEntryResponse(
                            "SECURE_NOTE",
                            null,
                            null,
                            null,
                            false,
                            null,
                            false,
                            List.of(field("body", "SECRET", true, true))),
                    new SecretTypeCatalogEntryResponse(
                            "SSH_KEY",
                            CATEGORY_DEVELOPMENT,
                            "ssh",
                            "openssh",
                            false,
                            null,
                            false,
                            List.of(
                                    field("publicKey", "TEXT", true, true),
                                    field("privateKey", "SECRET", true, true),
                                    field("passphrase", "SECRET", false, true))),
                    new SecretTypeCatalogEntryResponse(
                            "API_TOKEN",
                            CATEGORY_DEVELOPMENT,
                            "api",
                            null,
                            false,
                            null,
                            false,
                            List.of(
                                    field("token", "SECRET", true, true),
                                    field("notes", "SECRET", false, true))),
                    new SecretTypeCatalogEntryResponse(
                            "GPG_KEY",
                            CATEGORY_DEVELOPMENT,
                            "gpg",
                            "gpg",
                            false,
                            null,
                            false,
                            List.of(
                                    field("publicKey", "TEXT", true, true),
                                    field("privateKey", "SECRET", true, true),
                                    field("passphrase", "SECRET", false, true))),
                    new SecretTypeCatalogEntryResponse(
                            "MFA_SECRET",
                            CATEGORY_COMMUNICATION,
                            null,
                            null,
                            false,
                            null,
                            false,
                            List.of(
                                    field("secret", "SECRET", true, true),
                                    field("recoveryCodes", "SECRET", false, true))),
                    new SecretTypeCatalogEntryResponse(
                            "CERTIFICATE",
                            CATEGORY_DEVELOPMENT,
                            "x509",
                            "x509",
                            false,
                            null,
                            false,
                            List.of(
                                    field("certificate", "TEXT", true, true),
                                    field("privateKey", "SECRET", true, true),
                                    field("passphrase", "SECRET", false, true))),
                    new SecretTypeCatalogEntryResponse(
                            "GENERIC_SECRET", null, null, null, true, "SECRET", true, List.of()));

    private RecordSecretTypes() {}

    static boolean isSupported(@NonNull String secretType) {
        return ALLOWED.contains(secretType);
    }

    static @NonNull List<SecretTypeCatalogEntryResponse> catalog() {
        return CATALOG;
    }

    private static @NonNull SecretTypeFieldCatalogResponse field(
            @NonNull String name, @NonNull String fieldType, boolean required, boolean revealable) {
        return new SecretTypeFieldCatalogResponse(name, fieldType, required, revealable);
    }
}
