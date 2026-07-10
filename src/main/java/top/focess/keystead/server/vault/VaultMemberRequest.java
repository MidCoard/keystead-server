package top.focess.keystead.server.vault;

import org.jspecify.annotations.NonNull;

public record VaultMemberRequest(@NonNull VaultMemberRole role) {}
