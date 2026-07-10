package top.focess.keystead.server.automation;

import jakarta.validation.constraints.NotBlank;
import org.jspecify.annotations.NonNull;

record RevokeAutomationTokenRequest(@NotBlank @NonNull String token) {}
