package top.focess.keystead.server.share;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.ConcurrentHashMap;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

/**
 * In-memory fixed-window rate limiter for the share endpoints. Mint requests are keyed by the
 * authenticated owner id; redeem requests are keyed by client IP. Each key gets its own one-minute
 * window; once the configured ceiling is reached within the window further requests are rejected
 * until the window rolls over to the next minute.
 *
 * <p>State is held in process memory: it is not shared across instances and resets on restart,
 * which is the intended pre-release behaviour. The redeem key is derived from {@code
 * X-Forwarded-For} (first hop) when present, otherwise the raw remote address; behind a trusted
 * reverse proxy this is correct, but an untrusted client can spoof the header to spread load across
 * keys, which is an accepted limitation for the pre-release limiter.
 */
@Component
class ShareRateLimiter {

    private final int mintPerMinute;
    private final int redeemPerMinute;
    private final Clock clock;
    private final ConcurrentHashMap<String, Window> mintWindows = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Window> redeemWindows = new ConcurrentHashMap<>();

    ShareRateLimiter(@NonNull ShareProperties properties, @NonNull Clock clock) {
        this.mintPerMinute = properties.mintRateLimitPerMinute();
        this.redeemPerMinute = properties.redeemRateLimitPerMinute();
        this.clock = clock;
    }

    /**
     * Records a mint request against the owner's current minute window.
     *
     * @return {@code true} if the request is within the configured ceiling, {@code false} if the
     *     owner has exhausted its quota for the current minute.
     */
    boolean tryAcquireMint(@NonNull String ownerId) {
        return tryAcquire(ownerId, mintPerMinute, mintWindows);
    }

    /**
     * Records a redeem request against the client IP's current minute window.
     *
     * @return {@code true} if the request is within the configured ceiling, {@code false} if the
     *     client has exhausted its quota for the current minute.
     */
    boolean tryAcquireRedeem(@NonNull String clientIp) {
        return tryAcquire(clientIp, redeemPerMinute, redeemWindows);
    }

    private boolean tryAcquire(
            @NonNull String key, int ceiling, @NonNull ConcurrentHashMap<String, Window> windows) {
        long minute = clock.instant().truncatedTo(ChronoUnit.MINUTES).toEpochMilli();
        Window current =
                windows.compute(
                        key,
                        (ignored, existing) -> {
                            if (existing == null || existing.minute() != minute) {
                                return new Window(minute, 1);
                            }
                            return new Window(minute, existing.count() + 1);
                        });
        return current.count() <= ceiling;
    }

    private record Window(long minute, int count) {}
}
