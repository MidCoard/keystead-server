package top.focess.keystead.server.automation;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.ConcurrentHashMap;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

/**
 * In-memory per-token fixed-window rate limiter for automation endpoints. Each distinct token id
 * gets its own one-minute window; once the configured ceiling is reached within the window further
 * requests are rejected until the window rolls over to the next minute.
 *
 * <p>State is keyed by token id and held in process memory: it is not shared across instances and
 * resets on restart, which is the intended pre-release behaviour. Entries for revoked tokens are
 * not eagerly evicted but are overwritten when a new token reuses a slot only on rollover; the map
 * is bounded in practice by the number of distinct tokens ever issued.
 */
@Component
class AutomationRateLimiter {

    private final int requestsPerMinute;
    private final Clock clock;
    private final ConcurrentHashMap<String, Window> windows = new ConcurrentHashMap<>();

    AutomationRateLimiter(@NonNull AutomationProperties properties, @NonNull Clock clock) {
        this.requestsPerMinute = properties.rateLimitRequestsPerMinute();
        this.clock = clock;
    }

    /**
     * Records a request against the token's current minute window.
     *
     * @return {@code true} if the request is within the configured ceiling, {@code false} if the
     *     token has exhausted its quota for the current minute.
     */
    boolean tryAcquire(@NonNull String tokenId) {
        long minute = clock.instant().truncatedTo(ChronoUnit.MINUTES).toEpochMilli();
        Window current =
                windows.compute(
                        tokenId,
                        (key, existing) -> {
                            if (existing == null || existing.minute() != minute) {
                                return new Window(minute, 1);
                            }
                            return new Window(minute, existing.count() + 1);
                        });
        return current.count() <= requestsPerMinute;
    }

    private record Window(long minute, int count) {}
}
