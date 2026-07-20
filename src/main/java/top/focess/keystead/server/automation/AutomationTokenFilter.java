package top.focess.keystead.server.automation;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public final class AutomationTokenFilter extends OncePerRequestFilter {

    private static final String AUTOMATION_PREFIX = "Automation ";
    private static final String RETRY_AFTER_SECONDS = "60";

    private final AutomationService automation;
    private final AutomationRateLimiter rateLimiter;

    AutomationTokenFilter(
            @NonNull AutomationService automation, @NonNull AutomationRateLimiter rateLimiter) {
        this.automation = automation;
        this.rateLimiter = rateLimiter;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        @Nullable String authorization = request.getHeader("Authorization");
        if (authorization != null
                && authorization.startsWith(AUTOMATION_PREFIX)
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            @Nullable AutomationTokenSubject subject =
                    automation
                            .authenticate(authorization.substring(AUTOMATION_PREFIX.length()))
                            .orElse(null);
            if (subject != null) {
                if (!rateLimiter.tryAcquire(subject.tokenId())) {
                    response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                    response.setHeader("Retry-After", RETRY_AFTER_SECONDS);
                    return;
                }
                SecurityContextHolder.getContext()
                        .setAuthentication(new AutomationAuthentication(subject));
            }
        }
        filterChain.doFilter(request, response);
    }
}
