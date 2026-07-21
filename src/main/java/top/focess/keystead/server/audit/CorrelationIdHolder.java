package top.focess.keystead.server.audit;

import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

/**
 * Request-scoped correlation id carrier backed by a {@link ThreadLocal}. Populated by {@link
 * CorrelationIdFilter} for the duration of a request so audit events appended during that request
 * can be traced back to it. The filter always {@linkplain #clear() clears} the value in a finally
 * block, so outside a request {@link #current()} is {@code null} and audit events recorded without
 * a request context (scheduled tasks, direct repository calls) carry no correlation id.
 */
@Component
public final class CorrelationIdHolder {

    private final ThreadLocal<@Nullable String> current = new ThreadLocal<>();

    public void set(@Nullable String correlationId) {
        if (correlationId == null || correlationId.isBlank()) {
            current.remove();
        } else {
            current.set(correlationId);
        }
    }

    public @Nullable String current() {
        return current.get();
    }

    public void clear() {
        current.remove();
    }
}
