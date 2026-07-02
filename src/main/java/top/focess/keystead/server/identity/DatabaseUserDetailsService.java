package top.focess.keystead.server.identity;

import org.jspecify.annotations.NonNull;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
class DatabaseUserDetailsService implements UserDetailsService {

    private final UserRepository users;

    DatabaseUserDetailsService(@NonNull UserRepository users) {
        this.users = users;
    }

    @Override
    public @NonNull UserDetails loadUserByUsername(@NonNull String username)
            throws UsernameNotFoundException {
        return users.find(username)
                .map(
                        user ->
                                User.withUsername(user.username())
                                        .password(user.passwordHash())
                                        .roles("USER")
                                        .build())
                .orElseThrow(() -> new UsernameNotFoundException(username));
    }
}
