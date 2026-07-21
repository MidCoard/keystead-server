package top.focess.keystead.server.audit;

import java.time.Duration;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Bounds for the audit trail. Bound from {@code keystead.audit.*}.
 *
 * @param retention how long audit events are kept per owner; when a new event is recorded, older
 *     events past {@code now - retention} are pruned for that owner. {@code null} (or a
 *     zero/negative duration) disables retention pruning entirely.
 * @param queryMaxLimit the largest page a caller may request from the audit query API. Defaults to
 *     200 when unset or non-positive.
 */
@ConfigurationProperties(prefix = "keystead.audit")
public record AuditProperties(@Nullable Duration retention, int queryMaxLimit) {

    public AuditProperties {
        if (retention == null || retention.isNegative() || retention.isZero()) {
            retention = null;
        }
        if (queryMaxLimit <= 0) {
            queryMaxLimit = 200;
        }
    }
}
