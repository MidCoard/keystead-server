package top.focess.keystead.server.share;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link ShareRateLimiter} using a mutable clock so the one-minute fixed window can
 * be advanced deterministically without sleeping. Covers ceiling enforcement for both the mint and
 * redeem ceilings, window-rollover recovery, and per-key isolation.
 */
class ShareRateLimiterTest {

    @Test
    void tryAcquireMintAllowsUpToCeilingThenRejects() {
        MutableClock clock = new MutableClock(Instant.parse("2026-07-25T00:00:00Z"));
        ShareRateLimiter limiter =
                new ShareRateLimiter(
                        new ShareProperties(Duration.ofDays(7), Duration.ofDays(30), 3, 60), clock);

        assertTrue(limiter.tryAcquireMint("owner-a"), "request 1 should be allowed");
        assertTrue(limiter.tryAcquireMint("owner-a"), "request 2 should be allowed");
        assertTrue(limiter.tryAcquireMint("owner-a"), "request 3 should be allowed");
        assertFalse(limiter.tryAcquireMint("owner-a"), "request 4 should be throttled");
    }

    @Test
    void tryAcquireRedeemAllowsUpToCeilingThenRejects() {
        MutableClock clock = new MutableClock(Instant.parse("2026-07-25T00:00:00Z"));
        ShareRateLimiter limiter =
                new ShareRateLimiter(
                        new ShareProperties(Duration.ofDays(7), Duration.ofDays(30), 30, 2), clock);

        assertTrue(limiter.tryAcquireRedeem("1.2.3.4"));
        assertTrue(limiter.tryAcquireRedeem("1.2.3.4"));
        assertFalse(limiter.tryAcquireRedeem("1.2.3.4"));
    }

    @Test
    void tryAcquireRecoversAfterWindowRollover() {
        MutableClock clock = new MutableClock(Instant.parse("2026-07-25T00:00:30Z"));
        ShareRateLimiter limiter =
                new ShareRateLimiter(
                        new ShareProperties(Duration.ofDays(7), Duration.ofDays(30), 2, 2), clock);

        assertTrue(limiter.tryAcquireMint("owner-a"));
        assertTrue(limiter.tryAcquireMint("owner-a"));
        assertFalse(limiter.tryAcquireMint("owner-a"));

        clock.advance(Duration.ofMinutes(1));
        assertTrue(
                limiter.tryAcquireMint("owner-a"),
                "first request in the new window should be allowed");
        assertTrue(limiter.tryAcquireMint("owner-a"));
        assertFalse(limiter.tryAcquireMint("owner-a"));
    }

    @Test
    void tryAcquireIsolatesPerKey() {
        MutableClock clock = new MutableClock(Instant.parse("2026-07-25T00:00:00Z"));
        ShareRateLimiter limiter =
                new ShareRateLimiter(
                        new ShareProperties(Duration.ofDays(7), Duration.ofDays(30), 2, 2), clock);

        assertTrue(limiter.tryAcquireRedeem("1.1.1.1"));
        assertTrue(limiter.tryAcquireRedeem("1.1.1.1"));
        assertFalse(limiter.tryAcquireRedeem("1.1.1.1"));

        assertTrue(limiter.tryAcquireRedeem("2.2.2.2"), "a different client has its own window");
        assertTrue(limiter.tryAcquireRedeem("2.2.2.2"));
        assertFalse(limiter.tryAcquireRedeem("2.2.2.2"));
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
