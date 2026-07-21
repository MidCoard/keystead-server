package top.focess.keystead.server.audit;

import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Durable signing key for tamper-evident audit events. Unlike {@code AccessTokenService}'s
 * ephemeral in-process key, this key must persist across restarts so signatures already stored
 * remain verifiable; it therefore comes from configuration rather than being generated. A blank or
 * absent {@code key} disables signing (the default), leaving existing behavior unchanged.
 *
 * @param key base64-encoded HMAC key; blank or {@code null} disables signing.
 * @param algorithm JCE MAC algorithm; defaults to {@code HmacSHA256} when blank.
 */
@ConfigurationProperties(prefix = "keystead.audit.signing")
public record AuditSigningProperties(@Nullable String key, @Nullable String algorithm) {

    public AuditSigningProperties {
        if (algorithm == null || algorithm.isBlank()) {
            algorithm = "HmacSHA256";
        }
    }
}
