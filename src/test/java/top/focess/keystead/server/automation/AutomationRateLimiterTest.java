package top.focess.keystead.server.automation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link AutomationRateLimiter} using a mutable clock so the one-minute fixed window
 * can be advanced deterministically without sleeping. Covers ceiling enforcement, window-rollover
 * recovery, and per-token isolation.
 */
class AutomationRateLimiterTest {

    @Test
    void tryAcquireAllowsUpToCeilingThenRejects() {
        MutableClock clock = new MutableClock(Instant.parse("2026-07-11T00:00:00Z"));
        AutomationRateLimiter limiter =
                new AutomationRateLimiter(new AutomationProperties(Duration.ofDays(90), 3), clock);

        assertTrue(limiter.tryAcquire("token-a"), "request 1 should be allowed");
        assertTrue(limiter.tryAcquire("token-a"), "request 2 should be allowed");
        assertTrue(limiter.tryAcquire("token-a"), "request 3 should be allowed");
        assertFalse(limiter.tryAcquire("token-a"), "request 4 should be throttled");
    }

    @Test
    void tryAcquireRecoversAfterWindowRollover() {
        MutableClock clock = new MutableClock(Instant.parse("2026-07-11T00:00:30Z"));
        AutomationRateLimiter limiter =
                new AutomationRateLimiter(new AutomationProperties(Duration.ofDays(90), 2), clock);

        assertTrue(limiter.tryAcquire("token-a"));
        assertTrue(limiter.tryAcquire("token-a"));
        assertFalse(limiter.tryAcquire("token-a"));

        clock.advance(Duration.ofMinutes(1));
        assertTrue(
                limiter.tryAcquire("token-a"), "first request in the new window should be allowed");
        assertTrue(limiter.tryAcquire("token-a"));
        assertFalse(limiter.tryAcquire("token-a"));
    }

    @Test
    void tryAcquireIsolatesPerToken() {
        MutableClock clock = new MutableClock(Instant.parse("2026-07-11T00:00:00Z"));
        AutomationRateLimiter limiter =
                new AutomationRateLimiter(new AutomationProperties(Duration.ofDays(90), 2), clock);

        assertTrue(limiter.tryAcquire("token-a"));
        assertTrue(limiter.tryAcquire("token-a"));
        assertFalse(limiter.tryAcquire("token-a"));

        assertTrue(limiter.tryAcquire("token-b"), "a different token has its own window");
        assertTrue(limiter.tryAcquire("token-b"));
        assertFalse(limiter.tryAcquire("token-b"));
    }

    private static final class MutableClock extends Clock {
        private Instant instant;
        private final ZoneId zone = ZoneOffset.UTC;

        MutableClock(Instant instant) {
            this.instant = instant;
        }

        void advance(Duration duration) {
            this.instant = this.instant.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return zone;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}
