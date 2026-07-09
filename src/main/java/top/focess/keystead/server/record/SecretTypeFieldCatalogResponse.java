package top.focess.keystead.server.record;

import java.util.Objects;
import org.jspecify.annotations.NonNull;

record SecretTypeFieldCatalogResponse(
        @NonNull String name, @NonNull String fieldType, boolean required, boolean revealable) {

    SecretTypeFieldCatalogResponse {
        requireNotBlank(name, "name");
        requireNotBlank(fieldType, "fieldType");
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
