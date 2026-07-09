package top.focess.keystead.server.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;

@Service
public final class AccessTokenService {

    private static final Duration ACCESS_TOKEN_TTL = Duration.ofMinutes(15);
    private static final String VERSION = "kst1";
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final Clock clock;
    private final byte[] signingKey;

    public AccessTokenService(@NonNull Clock clock) {
        this.clock = clock;
        this.signingKey = new byte[32];
        new SecureRandom().nextBytes(signingKey);
    }

    public @NonNull IssuedAccessToken issue(@NonNull String username) {
        Instant expiresAt = clock.instant().plus(ACCESS_TOKEN_TTL);
        String user = b64(username.getBytes(StandardCharsets.UTF_8));
        String body =
                VERSION + "." + user + "." + expiresAt.getEpochSecond() + "." + UUID.randomUUID();
        return new IssuedAccessToken(body + "." + sign(body), expiresAt);
    }

    public @NonNull Optional<String> authenticate(@NonNull String token) {
        try {
            String[] parts = token.split("\\.", -1);
            if (parts.length != 5 || !VERSION.equals(parts[0])) {
                return Optional.empty();
            }
            String body = parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3];
            if (!MessageDigest.isEqual(
                    sign(body).getBytes(StandardCharsets.US_ASCII),
                    parts[4].getBytes(StandardCharsets.US_ASCII))) {
                return Optional.empty();
            }
            Instant expiresAt = Instant.ofEpochSecond(Long.parseLong(parts[2]));
            if (!expiresAt.isAfter(clock.instant())) {
                return Optional.empty();
            }
            return Optional.of(
                    new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    private @NonNull String sign(@NonNull String body) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(signingKey, HMAC_ALGORITHM));
            return b64(mac.doFinal(body.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("Could not sign access token", e);
        }
    }

    private static @NonNull String b64(byte @NonNull [] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public record IssuedAccessToken(@NonNull String token, @NonNull Instant expiresAt) {}
}
