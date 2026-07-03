package top.focess.keystead.server.crypto;

import org.jspecify.annotations.NonNull;

record CryptoAlgorithmDefaultsResponse(
        @NonNull String payloadAead,
        @NonNull String vaultKeyKdf,
        @NonNull String vaultKeyPackage) {}
