package top.focess.keystead.server.auth;

import org.jspecify.annotations.NonNull;

interface RefreshTokenRepositoryWrites {

    void insert(@NonNull StoredRefreshToken token);

    void update(@NonNull StoredRefreshToken token);
}
