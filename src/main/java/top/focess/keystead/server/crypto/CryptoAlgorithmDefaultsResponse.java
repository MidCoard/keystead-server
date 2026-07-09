package top.focess.keystead.server.crypto;

import java.util.Objects;
import org.jspecify.annotations.NonNull;

record CryptoAlgorithmDefaultsResponse(
        @NonNull String payloadAead, @NonNull String vaultKeyKdf, @NonNull String vaultKeyPackage) {

    CryptoAlgorithmDefaultsResponse {
        requireNotBlank(payloadAead, "payloadAead");
        requireNotBlank(vaultKeyKdf, "vaultKeyKdf");
        requireNotBlank(vaultKeyPackage, "vaultKeyPackage");
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
