package top.focess.keystead.server.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Base64;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

class AccessTokenServiceTest {

    @Test
    void issuedTokenAuthenticatesUntilItExpires() {
        MutableClock clock = new MutableClock(Instant.parse("2026-07-09T00:00:00Z"));
        AccessTokenService service = new AccessTokenService(clock);
        AccessTokenService.IssuedAccessToken token = service.issue("alice");

        assertEquals("alice", service.authenticate(token.token()).orElseThrow());

        clock.now = token.expiresAt();

        assertTrue(service.authenticate(token.token()).isEmpty());
    }

    @Test
    void tamperedTokenIsRejected() {
        MutableClock clock = new MutableClock(Instant.parse("2026-07-09T00:00:00Z"));
        AccessTokenService service = new AccessTokenService(clock);
        String token = service.issue("alice").token();
        String[] parts = token.split("\\.", -1);
        parts[1] = Base64.getUrlEncoder().withoutPadding().encodeToString("bob".getBytes());

        assertTrue(service.authenticate(String.join(".", parts)).isEmpty());
        assertTrue(service.authenticate(token.substring(0, token.length() - 2) + "aa").isEmpty());
        assertTrue(service.authenticate("kst1.not-base64.not-a-time.value.signature").isEmpty());
    }

    private static final class MutableClock extends Clock {

        private Instant now;

        private MutableClock(@NonNull Instant now) {
            this.now = now;
        }

        @Override
        public @NonNull ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public @NonNull Clock withZone(@NonNull ZoneId zone) {
            return this;
        }

        @Override
        public @NonNull Instant instant() {
            return now;
        }
    }
}
