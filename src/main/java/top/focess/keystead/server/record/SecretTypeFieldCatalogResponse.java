package top.focess.keystead.server.record;

import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.model.SecretFieldSchema;

record SecretTypeFieldCatalogResponse(
        @NonNull String name,
        @NonNull String fieldType,
        boolean required,
        boolean revealable,
        @NonNull List<String> importAliases,
        @NonNull String exportName,
        @Nullable Integer maxLength) {

    SecretTypeFieldCatalogResponse(
            @NonNull String name, @NonNull String fieldType, boolean required, boolean revealable) {
        this(name, fieldType, required, revealable, List.of(), name, null);
    }

    SecretTypeFieldCatalogResponse {
        requireNotBlank(name, "name");
        requireNotBlank(fieldType, "fieldType");
        importAliases = List.copyOf(Objects.requireNonNull(importAliases, "importAliases"));
        requireNotBlank(exportName, "exportName");
        if (maxLength != null && maxLength <= 0) {
            throw new IllegalArgumentException("maxLength must be positive");
        }
    }

    static @NonNull SecretTypeFieldCatalogResponse from(@NonNull SecretFieldSchema field) {
        return new SecretTypeFieldCatalogResponse(
                field.name(),
                field.type().name(),
                field.required(),
                field.revealable(),
                field.importAliases(),
                field.exportName(),
                field.maxLength());
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
