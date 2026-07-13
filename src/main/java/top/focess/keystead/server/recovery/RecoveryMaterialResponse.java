package top.focess.keystead.server.recovery;

import java.util.List;
import org.jspecify.annotations.NonNull;

public record RecoveryMaterialResponse(
        @NonNull String enrollmentId,
        long generation,
        @NonNull String wrappingAlgorithm,
        @NonNull String encryptedPrivateKey,
        @NonNull List<RecoveryVaultPackageResponse> vaultPackages) {

    public RecoveryMaterialResponse {
        vaultPackages = List.copyOf(vaultPackages);
    }

    @Override
    public @NonNull String toString() {
        return "RecoveryMaterialResponse[enrollmentId=%s, generation=%d, wrappingAlgorithm=%s, encryptedPrivateKey=[REDACTED %d chars], vaultPackages=%d]"
                .formatted(
                        enrollmentId,
                        generation,
                        wrappingAlgorithm,
                        encryptedPrivateKey.length(),
                        vaultPackages.size());
    }
}
