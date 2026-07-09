package top.focess.keystead.server.identity;

import org.jspecify.annotations.NonNull;

interface UserRepositoryWrites {

    void insert(@NonNull StoredUser user);
}
