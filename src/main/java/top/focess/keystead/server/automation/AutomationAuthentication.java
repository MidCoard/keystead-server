package top.focess.keystead.server.automation;

import org.jspecify.annotations.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

public final class AutomationAuthentication extends AbstractAuthenticationToken {

    private final AutomationTokenSubject subject;

    public AutomationAuthentication(@NonNull AutomationTokenSubject subject) {
        super(AuthorityUtils.createAuthorityList("ROLE_AUTOMATION"));
        this.subject = subject;
        setAuthenticated(true);
    }

    @Override
    public @NonNull Object getCredentials() {
        return "N/A";
    }

    @Override
    public @NonNull AutomationTokenSubject getPrincipal() {
        return subject;
    }

    @Override
    public @NonNull String getName() {
        return subject.principalId();
    }
}
