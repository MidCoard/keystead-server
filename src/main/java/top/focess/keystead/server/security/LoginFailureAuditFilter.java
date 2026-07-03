package top.focess.keystead.server.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import top.focess.keystead.server.audit.AuditService;

@Component
public class LoginFailureAuditFilter extends OncePerRequestFilter {

    private static final String BASIC_PREFIX = "Basic ";

    private final AuditService audit;

    public LoginFailureAuditFilter(@NonNull AuditService audit) {
        this.audit = audit;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        filterChain.doFilter(request, response);
        if (response.getStatus() == HttpStatus.UNAUTHORIZED.value()) {
            @Nullable String username = basicUsername(request.getHeader(HttpHeaders.AUTHORIZATION));
            if (username != null && !username.isBlank()) {
                audit.loginFailed(username);
            }
        }
    }

    private static @Nullable String basicUsername(@Nullable String authorization) {
        if (authorization == null || !authorization.startsWith(BASIC_PREFIX)) {
            return null;
        }
        try {
            String decoded =
                    new String(
                            Base64.getDecoder()
                                    .decode(authorization.substring(BASIC_PREFIX.length())),
                            StandardCharsets.UTF_8);
            int separator = decoded.indexOf(':');
            if (separator < 0) {
                return null;
            }
            return decoded.substring(0, separator);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
