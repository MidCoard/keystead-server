package top.focess.keystead.server.share;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Bounds for hosted shares. Bound from {@code keystead.share.*}.
 *
 * @param defaultTtl the lifetime applied when a mint request omits {@code expiresAt}; defaults to 7
 *     days.
 * @param maxTtl the maximum lifetime any share may have; {@code mint} rejects any expiry further
 *     out than {@code now + maxTtl}. Defaults to 30 days.
 * @param mintRateLimitPerMinute per-owner ceiling on mint requests within a rolling minute for an
 *     authenticated user. Defaults to 30.
 * @param redeemRateLimitPerMinute per-client-ip ceiling on public redeem requests within a rolling
 *     minute. Defaults to 60.
 */
@ConfigurationProperties(prefix = "keystead.share")
public record ShareProperties(
        Duration defaultTtl,
        Duration maxTtl,
        int mintRateLimitPerMinute,
        int redeemRateLimitPerMinute) {

    public ShareProperties {
        if (defaultTtl == null || defaultTtl.isNegative() || defaultTtl.isZero()) {
            defaultTtl = Duration.ofDays(7);
        }
        if (maxTtl == null || maxTtl.isNegative() || maxTtl.isZero()) {
            maxTtl = Duration.ofDays(30);
        }
        if (maxTtl.compareTo(defaultTtl) < 0) {
            maxTtl = defaultTtl;
        }
        if (mintRateLimitPerMinute <= 0) {
            mintRateLimitPerMinute = 30;
        }
        if (redeemRateLimitPerMinute <= 0) {
            redeemRateLimitPerMinute = 60;
        }
    }
}
