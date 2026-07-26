package top.focess.keystead.server.vault;

import java.time.Instant;
import org.jspecify.annotations.NonNull;

public record VaultMemberResponse(
        @NonNull String fingerprint,
        @NonNull String userId,
        @NonNull VaultMemberRole role,
        @NonNull VaultMemberState state,
        @NonNull Instant createdAt,
        @NonNull Instant updatedAt) {
    static @NonNull VaultMemberResponse from(@NonNull StoredVaultMember member) {
        return new VaultMemberResponse(
                member.fingerprint(),
                member.userId(),
                member.role(),
                member.state(),
                member.createdAt(),
                member.updatedAt());
    }
}
