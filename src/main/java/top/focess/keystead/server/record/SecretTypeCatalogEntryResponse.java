package top.focess.keystead.server.record;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.model.SecretTypeCatalogEntry;

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
        requireUniqueFieldNames(fields);
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

    private static void requireUniqueFieldNames(
            @NonNull List<SecretTypeFieldCatalogResponse> fields) {
        Set<String> names =
                fields.stream()
                        .map(SecretTypeFieldCatalogResponse::name)
                        .collect(Collectors.toSet());
        if (names.size() != fields.size()) {
            throw new IllegalArgumentException("fields must not contain duplicate names");
        }
    }

    static @NonNull SecretTypeCatalogEntryResponse from(@NonNull SecretTypeCatalogEntry entry) {
        return new SecretTypeCatalogEntryResponse(
                entry.type().name(),
                entry.defaultCategory(),
                entry.defaultProvider(),
                entry.defaultSoftware(),
                entry.allowsCustomFields(),
                entry.customFieldType() == null ? null : entry.customFieldType().name(),
                entry.customFieldsRevealable(),
                entry.fields().stream().map(SecretTypeFieldCatalogResponse::from).toList());
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
