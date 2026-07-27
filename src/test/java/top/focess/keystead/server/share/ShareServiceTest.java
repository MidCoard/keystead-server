package top.focess.keystead.server.share;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.validation.Validator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link ShareService} using a fixed clock so the expiry and burn-after-reading
 * paths can be exercised deterministically without sleeping. The HTTP layer covers the happy paths;
 * these tests pin the time-sensitive delete/keep behaviour.
 */
class ShareServiceTest {

    private static final Instant NOW = Instant.parse("2026-07-25T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    @Test
    void redeemDeletesAndReportsExpiredShare() {
        ShareRepository shares = mock(ShareRepository.class);
        ShareService service = newService(shares);
        Share expired =
                new Share(
                        "code",
                        "owner",
                        "payload",
                        true,
                        NOW.minusSeconds(1),
                        NOW.minusSeconds(60));
        when(shares.find("code")).thenReturn(Optional.of(expired));

        assertThrows(ShareExpiredException.class, () -> service.redeem("code", "1.2.3.4"));
        verify(shares).remove(expired);
    }

    @Test
    void redeemBurnsAfterReading() {
        ShareRepository shares = mock(ShareRepository.class);
        ShareService service = newService(shares);
        Share share =
                new Share(
                        "code",
                        "owner",
                        "payload",
                        true,
                        NOW.plusSeconds(60),
                        NOW.minusSeconds(60));
        when(shares.find("code")).thenReturn(Optional.of(share));

        RedeemShareResponse response = service.redeem("code", "1.2.3.4");
        assertEquals("payload", response.payload());
        verify(shares).remove(share);
    }

    @Test
    void redeemKeepsNonBurningShare() {
        ShareRepository shares = mock(ShareRepository.class);
        ShareService service = newService(shares);
        Share share =
                new Share(
                        "code",
                        "owner",
                        "payload",
                        false,
                        NOW.plusSeconds(60),
                        NOW.minusSeconds(60));
        when(shares.find("code")).thenReturn(Optional.of(share));

        RedeemShareResponse response = service.redeem("code", "1.2.3.4");
        assertEquals("payload", response.payload());
        verify(shares, never()).remove(any(Share.class));
    }

    private static ShareService newService(ShareRepository shares) {
        ShareRateLimiter rateLimiter = mock(ShareRateLimiter.class);
        when(rateLimiter.tryAcquireMint(anyString())).thenReturn(true);
        when(rateLimiter.tryAcquireRedeem(anyString())).thenReturn(true);
        return new ShareService(
                shares,
                rateLimiter,
                CLOCK,
                mock(Validator.class),
                new ShareProperties(Duration.ofDays(7), Duration.ofDays(30), 30, 60));
    }
}
