package top.focess.keystead.server.record;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

record SecretTypeCatalogResponse(@NonNull List<SecretTypeCatalogEntryResponse> types) {

    SecretTypeCatalogResponse {
        types = List.copyOf(Objects.requireNonNull(types, "types"));
        if (types.isEmpty()) {
            throw new IllegalArgumentException("types must not be empty");
        }
        LinkedHashSet<String> uniqueTypes = new LinkedHashSet<>();
        for (SecretTypeCatalogEntryResponse type : types) {
            if (!uniqueTypes.add(type.type())) {
                throw new IllegalArgumentException("types must be unique");
            }
        }
    }

    static @NonNull SecretTypeCatalogResponse fromRecordTypes() {
        return new SecretTypeCatalogResponse(RecordSecretTypes.catalog());
    }
}
