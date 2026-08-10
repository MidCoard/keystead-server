package top.focess.keystead.server.identity;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import java.time.Clock;
import java.time.Instant;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
class IdentityService {

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final Clock clock;
    private final Validator validator;
    private final RegistrationProperties registrationProperties;

    IdentityService(
            @NonNull UserRepository users,
            @NonNull PasswordEncoder passwordEncoder,
            @NonNull Clock clock,
            @NonNull Validator validator,
            @NonNull RegistrationProperties registrationProperties) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.clock = clock;
        this.validator = validator;
        this.registrationProperties = registrationProperties;
    }

    @Transactional
    void register(@NonNull UserRegistrationRequest request) {
        if (!registrationProperties.enabled()) {
            throw new RegistrationClosedException("Registration is disabled");
        }
        int maxUsers = registrationProperties.maxUsers();
        // A concurrent registration can let the count briefly exceed the cap by one; acceptable
        // for a self-hosted server - a strict cap would need a database lock.
        if (maxUsers > 0 && users.count() >= maxUsers) {
            throw new RegistrationClosedException("Registration user limit reached");
        }
        if (users.exists(request.username())) {
            throw new UserAlreadyExistsException("User already exists");
        }
        validate(request);
        Instant now = clock.instant();
        users.insert(
                new StoredUser(
                        request.username(),
                        passwordEncoder.encode(request.password()),
                        now,
                        now,
                        0L));
    }

    private void validate(@NonNull UserRegistrationRequest request) {
        Set<ConstraintViolation<UserRegistrationRequest>> violations = validator.validate(request);
        if (!violations.isEmpty()) {
            throw new InvalidUserRegistrationRequestException(
                    violations.iterator().next().getPropertyPath() + " is invalid");
        }
    }
}
