package top.focess.keystead.server.automation;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Bounds for automation tokens. Bound from {@code keystead.automation.*}.
 *
 * @param tokenMaxTtl the maximum lifetime an issued token may have; {@code issueToken} rejects any
 *     expiry further out than {@code now + tokenMaxTtl}. Defaults to 90 days.
 * @param rateLimitRequestsPerMinute per-token ceiling on automation endpoint requests within a
 *     rolling minute. Defaults to 120.
 */
@ConfigurationProperties(prefix = "keystead.automation")
public record AutomationProperties(Duration tokenMaxTtl, int rateLimitRequestsPerMinute) {

    public AutomationProperties {
        if (tokenMaxTtl == null || tokenMaxTtl.isNegative() || tokenMaxTtl.isZero()) {
            tokenMaxTtl = Duration.ofDays(90);
        }
        if (rateLimitRequestsPerMinute <= 0) {
            rateLimitRequestsPerMinute = 120;
        }
    }
}
