package top.focess.keystead.server.audit;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Propagates a per-request correlation id for audit traceability. Honors an inbound {@code
 * X-Correlation-Id} header only when it is a safe, length-bounded token; otherwise generates a
 * fresh UUID. The resolved id is published to {@link CorrelationIdHolder} for the duration of the
 * request and echoed back on the response.
 *
 * <p>Runs at the highest precedence so it wraps the security filter chain and any downstream
 * audit-emitting filter (such as login-failure recording) observes the same correlation id.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorrelationIdFilter extends OncePerRequestFilter {

    static final String CORRELATION_ID_HEADER = "X-Correlation-Id";

    private static final Pattern ACCEPTED_ID = Pattern.compile("^[A-Za-z0-9_-]{1,64}$");

    private final CorrelationIdHolder holder;

    CorrelationIdFilter(@NonNull CorrelationIdHolder holder) {
        this.holder = holder;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        String correlationId = resolve(request.getHeader(CORRELATION_ID_HEADER));
        response.setHeader(CORRELATION_ID_HEADER, correlationId);
        holder.set(correlationId);
        try {
            filterChain.doFilter(request, response);
        } finally {
            holder.clear();
        }
    }

    private static @NonNull String resolve(@Nullable String header) {
        if (header != null && ACCEPTED_ID.matcher(header).matches()) {
            return header;
        }
        return UUID.randomUUID().toString();
    }
}
