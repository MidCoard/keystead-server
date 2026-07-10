package top.focess.keystead.server.record;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecretTypeCatalog;

final class RecordSecretTypes {

    private static final Set<String> ALLOWED =
            SecretTypeCatalog.defaults().stream()
                    .map(entry -> entry.type().name())
                    .collect(Collectors.toUnmodifiableSet());

    private static final List<SecretTypeCatalogEntryResponse> CATALOG =
            SecretTypeCatalog.defaults().stream()
                    .map(SecretTypeCatalogEntryResponse::from)
                    .toList();

    private RecordSecretTypes() {}

    static boolean isSupported(@NonNull String secretType) {
        return ALLOWED.contains(secretType);
    }

    static @NonNull List<SecretTypeCatalogEntryResponse> catalog() {
        return CATALOG;
    }
}
