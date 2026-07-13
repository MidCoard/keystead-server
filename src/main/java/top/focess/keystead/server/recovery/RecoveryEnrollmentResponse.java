package top.focess.keystead.server.recovery;

import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public record RecoveryEnrollmentResponse(
        @NonNull String enrollmentId,
        long generation,
        @NonNull RecoveryEnrollmentState state,
        @NonNull String wrappingAlgorithm,
        @NonNull String wrappingPublicKey,
        @NonNull Instant createdAt,
        @Nullable Instant committedAt) {

    static @NonNull RecoveryEnrollmentResponse from(@NonNull RecoveryEnrollmentEntity entity) {
        return new RecoveryEnrollmentResponse(
                entity.id.enrollmentId,
                entity.id.generation,
                entity.state,
                entity.wrappingAlgorithm,
                entity.wrappingPublicKey,
                entity.createdAt,
                entity.committedAt);
    }
}
