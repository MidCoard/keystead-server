package top.focess.keystead.server.audit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

/**
 * Computes and checks tamper-evident HMAC signatures over audit events so a verifier holding the
 * configured key can detect any modification of a stored row (DB-only compromise threat model).
 * Mirrors {@code AccessTokenService}'s HMAC-SHA256 + constant-time compare, but binds the key to
 * durable configuration so signatures survive restarts. Signing is disabled when no key is
 * configured, in which case {@link #sign} returns {@code null} and rows are stored unsigned.
 *
 * <p>The signed contract is the canonical encoding of the eleven {@link StoredAuditEvent} fields:
 * each field is base64-encoded (null becomes empty), joined with {@code .} (which never appears in
 * base64 output, so the delimiter is unambiguous). {@code correlationId} is deliberately excluded -
 * it is transport metadata, not part of the audited record.
 */
@Component
public final class AuditSigner {

    private static final Base64.Encoder ENCODER = Base64.getEncoder();

    private final String algorithm;
    @Nullable private final SecretKeySpec key;

    public AuditSigner(@NonNull AuditSigningProperties properties) {
        this.algorithm = properties.algorithm();
        String encoded = properties.key();
        this.key = encoded == null || encoded.isBlank() ? null : decodeKey(encoded);
    }

    /**
     * @return {@code true} when a signing key is configured.
     */
    public boolean isEnabled() {
        return key != null;
    }

    /**
     * @return the base64 HMAC-SHA256 signature over the canonical encoding, or {@code null} when
     *     signing is disabled.
     */
    public @Nullable String sign(@NonNull StoredAuditEvent event) {
        if (key == null) {
            return null;
        }
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(key);
            byte[] digest = mac.doFinal(canonicalEncoding(event).getBytes(StandardCharsets.UTF_8));
            return ENCODER.encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("Could not sign audit event", e);
        }
    }

    /**
     * @return {@code true} iff signing is enabled and {@code signature} matches a recomputation
     *     over {@code event}. A {@code null} signature, or signing disabled, yields {@code false}.
     */
    public boolean verify(@NonNull StoredAuditEvent event, @Nullable String signature) {
        if (signature == null) {
            return false;
        }
        String expected = sign(event);
        if (expected == null) {
            return false;
        }
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                signature.getBytes(StandardCharsets.UTF_8));
    }

    static @NonNull String canonicalEncoding(@NonNull StoredAuditEvent event) {
        return String.join(
                ".",
                enc(event.eventId()),
                enc(event.ownerId()),
                enc(event.actorId()),
                enc(event.eventType()),
                enc(event.targetType()),
                enc(event.targetId()),
                enc(event.vaultId()),
                enc(event.revision() == null ? null : event.revision().toString()),
                enc(event.outcome()),
                enc(event.details()),
                enc(event.createdAt().toString()));
    }

    private @NonNull SecretKeySpec decodeKey(@NonNull String encoded) {
        try {
            return new SecretKeySpec(Base64.getDecoder().decode(encoded), algorithm);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("keystead.audit.signing.key is not valid base64", e);
        }
    }

    private static @NonNull String enc(@Nullable String value) {
        if (value == null) {
            return "";
        }
        return ENCODER.encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
