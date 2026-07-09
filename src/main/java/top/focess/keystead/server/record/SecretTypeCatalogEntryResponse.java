package top.focess.keystead.server.record;

import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

record SecretTypeCatalogEntryResponse(
        @NonNull String type,
        @Nullable String defaultCategory,
        @Nullable String defaultProvider,
        @Nullable String defaultSoftware,
        boolean allowsCustomFields,
        @Nullable String customFieldType,
        boolean customFieldsRevealable,
        @NonNull List<SecretTypeFieldCatalogResponse> fields) {

    SecretTypeCatalogEntryResponse {
        requireNotBlank(type, "type");
        requireNullableNotBlank(defaultCategory, "defaultCategory");
        requireNullableNotBlank(defaultProvider, "defaultProvider");
        requireNullableNotBlank(defaultSoftware, "defaultSoftware");
        requireNullableNotBlank(customFieldType, "customFieldType");
        fields = List.copyOf(Objects.requireNonNull(fields, "fields"));
        if (allowsCustomFields && customFieldType == null) {
            throw new IllegalArgumentException("customFieldType is required");
        }
        if (!allowsCustomFields && customFieldType != null) {
            throw new IllegalArgumentException("customFieldType requires custom fields");
        }
        if (!allowsCustomFields && customFieldsRevealable) {
            throw new IllegalArgumentException("custom fields cannot be revealable when disabled");
        }
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }

    private static void requireNullableNotBlank(@Nullable String value, @NonNull String field) {
        if (value != null && value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
