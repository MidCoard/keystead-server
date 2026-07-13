package top.focess.keystead.server.recovery;

import jakarta.validation.constraints.Positive;

public record RecoveryEnrollmentCommitRequest(@Positive long generation) {}
