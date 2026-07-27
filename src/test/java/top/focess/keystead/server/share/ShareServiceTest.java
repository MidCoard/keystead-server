package top.focess.keystead.server.share;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.validation.Validator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link ShareService} using a fixed clock so the expiry and burn-after-reading
 * paths can be exercised deterministically without sleeping. The HTTP layer covers the happy paths;
 * these tests pin the time-sensitive delete/keep behaviour and the atomic burn/delete contracts.
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
        verify(shares).deleteByCode("code");
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
        when(shares.deleteByCode("code")).thenReturn(1);

        RedeemShareResponse response = service.redeem("code", "1.2.3.4");
        assertEquals("payload", response.payload());
        verify(shares).deleteByCode("code");
    }

    @Test
    void redeemBurnLoserReportsNotFound() {
        // Another concurrent redeemer won the atomic delete between our read and our delete, so we
        // must not also return the payload.
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
        when(shares.deleteByCode("code")).thenReturn(0);

        assertThrows(ShareNotFoundException.class, () -> service.redeem("code", "1.2.3.4"));
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
        verify(shares, never()).deleteByCode(anyString());
    }

    @Test
    void listExcludesExpiredShares() {
        ShareRepository shares = mock(ShareRepository.class);
        ShareService service = newService(shares);
        Share expired =
                new Share("code-e", "owner", "p", false, NOW.minusSeconds(1), NOW.minusSeconds(60));
        Share live =
                new Share("code-l", "owner", "p", false, NOW.plusSeconds(60), NOW.minusSeconds(60));
        when(shares.listByOwner("owner")).thenReturn(List.of(expired, live));

        List<ShareSummary> summaries = service.list("owner");

        assertEquals(1, summaries.size());
        assertEquals("code-l", summaries.get(0).code());
    }

    @Test
    void deleteRemovesOwnerShareAtomically() {
        ShareRepository shares = mock(ShareRepository.class);
        ShareService service = newService(shares);
        when(shares.deleteByCodeAndOwner("code", "owner")).thenReturn(1);

        service.delete("owner", "code");

        verify(shares).deleteByCodeAndOwner("code", "owner");
    }

    @Test
    void deleteReportsNotFoundForMissingOrNonOwnedShare() {
        ShareRepository shares = mock(ShareRepository.class);
        ShareService service = newService(shares);
        when(shares.deleteByCodeAndOwner(eq("code"), eq("owner"))).thenReturn(0);

        assertThrows(ShareNotFoundException.class, () -> service.delete("owner", "code"));
    }

    @Test
    void purgeExpiredSharesDeletesExpiredRows() {
        ShareRepository shares = mock(ShareRepository.class);
        ShareService service = newService(shares);
        when(shares.deleteExpired(NOW)).thenReturn(3);

        service.purgeExpiredShares();

        verify(shares).deleteExpired(NOW);
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
