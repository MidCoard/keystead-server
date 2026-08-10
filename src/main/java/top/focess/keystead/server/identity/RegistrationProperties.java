package top.focess.keystead.server.identity;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Controls for open user registration. Bound from {@code keystead.registration.*}.
 *
 * <p>An internet-exposed server otherwise lets anyone self-register and write unbounded data; these
 * knobs let the operator close that door.
 *
 * @param enabled master switch; when {@code false} all registration is rejected with 403. Defaults
 *     to {@code true} so a fresh server can bootstrap its first user (there is no admin/bootstrap
 *     endpoint). The operator sets {@code false} once their users exist, or relies on {@code
 *     maxUsers} to auto-close.
 * @param maxUsers hard cap on the number of registered users; {@code 0} means unlimited. When
 *     {@code > 0}, registration is rejected with 403 once the cap is reached. Setting a cap below
 *     the current user count blocks new registrations but never deletes existing users.
 */
@ConfigurationProperties(prefix = "keystead.registration")
public record RegistrationProperties(Boolean enabled, int maxUsers) {

    public RegistrationProperties {
        if (enabled == null) {
            // Primitive boolean would default to false (closed); box and normalize so an unbound
            // property leaves registration open, preserving the bootstrap-first-user behaviour.
            enabled = true;
        }
        if (maxUsers < 0) {
            maxUsers = 0;
        }
    }
}
