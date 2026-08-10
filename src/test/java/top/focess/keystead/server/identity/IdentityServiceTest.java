package top.focess.keystead.server.identity;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.validation.Validator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Unit tests for the registration gating in {@link IdentityService}. The HTTP layer (see {@link
 * RegistrationDisabledHttpIntegrationTest}) covers the 403 response end-to-end; these tests pin the
 * enabled/cap checks and their ordering without a database, so they are independent of the CI
 * datasource lane (H2 vs PostgreSQL). A database-backed cap test would have to override the
 * datasource URL to isolate the user count, which collides with the Postgres lane's {@code
 * SPRING_DATASOURCE_DRIVER_CLASS_NAME} and is avoided here.
 */
class IdentityServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-10T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final UserRegistrationRequest REQUEST =
            new UserRegistrationRequest("alice", "password1234");

    @Test
    void registerRejectedWhenDisabled() {
        UserRepository users = mock(UserRepository.class);
        IdentityService service = newService(users, new RegistrationProperties(false, 0));

        assertThrows(RegistrationClosedException.class, () -> service.register(REQUEST));

        // Disabled registration must short-circuit before touching the database.
        verify(users, never()).count();
        verify(users, never()).exists(anyString());
        verify(users, never()).insert(any(StoredUser.class));
    }

    @Test
    void registerRejectedWhenUserCapReached() {
        UserRepository users = mock(UserRepository.class);
        when(users.count()).thenReturn(1L);
        IdentityService service = newService(users, new RegistrationProperties(true, 1));

        assertThrows(RegistrationClosedException.class, () -> service.register(REQUEST));

        // At the cap, registration fails before checking whether the username exists.
        verify(users, never()).exists(anyString());
        verify(users, never()).insert(any(StoredUser.class));
    }

    @Test
    void registerAllowedBelowCapInsertsUser() {
        UserRepository users = mock(UserRepository.class);
        when(users.count()).thenReturn(0L);
        when(users.exists("alice")).thenReturn(false);
        PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
        when(passwordEncoder.encode("password1234")).thenReturn("encoded");
        IdentityService service =
                newService(users, passwordEncoder, new RegistrationProperties(true, 1));

        service.register(REQUEST);

        verify(users).insert(new StoredUser("alice", "encoded", NOW, NOW, 0L));
    }

    private static IdentityService newService(
            UserRepository users, RegistrationProperties properties) {
        return newService(users, mock(PasswordEncoder.class), properties);
    }

    private static IdentityService newService(
            UserRepository users,
            PasswordEncoder passwordEncoder,
            RegistrationProperties properties) {
        return new IdentityService(
                users, passwordEncoder, CLOCK, mock(Validator.class), properties);
    }
}
