package top.focess.keystead.server.record;

import org.jspecify.annotations.NonNull;

record PersonalVaultMismatchResponse(
        @NonNull String code,
        @NonNull String serverFingerprint,
        @NonNull String submittedFingerprint) {}
