package top.focess.keystead.server.identity;

import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserTokenVersionService {

    private final UserRepository users;

    UserTokenVersionService(@NonNull UserRepository users) {
        this.users = users;
    }

    @Transactional(readOnly = true)
    public long tokenVersion(@NonNull String username) {
        return users.find(username).map(StoredUser::tokenVersion).orElse(-1L);
    }

    @Transactional
    public void incrementTokenVersion(@NonNull String username) {
        users.incrementTokenVersion(username);
    }
}
