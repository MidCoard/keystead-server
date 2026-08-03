package top.focess.keystead.server.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import org.jspecify.annotations.NonNull;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Wraps a delegate {@link PasswordEncoder} so the raw credential is pre-hashed with SHA-256 before
 * reaching the delegate. This is the standard pattern to bypass the 72-byte ceiling of bcrypt (and
 * any other keyed-hash scheme with a bounded input) without weakening the salt and work-factor that
 * the delegate applies. The pre-hash is deterministic and produces a 64-character lowercase hex
 * string, well under the 72-byte bcrypt limit.
 *
 * <p>The pre-hash must be applied in both {@link #encode(CharSequence)} and {@link
 * #matches(CharSequence, String)}; otherwise registration and authentication diverge and no login
 * could ever succeed.
 */
class PreHashedPasswordEncoder implements PasswordEncoder {

    private static final String ALGORITHM = "SHA-256";

    private final PasswordEncoder delegate;

    PreHashedPasswordEncoder(@NonNull PasswordEncoder delegate) {
        this.delegate = delegate;
    }

    @Override
    public @NonNull String encode(@NonNull CharSequence rawPassword) {
        return delegate.encode(prehash(rawPassword));
    }

    @Override
    public boolean matches(@NonNull CharSequence rawPassword, @NonNull String encodedPassword) {
        return delegate.matches(prehash(rawPassword), encodedPassword);
    }

    @Override
    public boolean upgradeEncoding(@NonNull String encodedPassword) {
        return delegate.upgradeEncoding(encodedPassword);
    }

    private static @NonNull String prehash(@NonNull CharSequence rawPassword) {
        try {
            byte[] digest =
                    MessageDigest.getInstance(ALGORITHM)
                            .digest(rawPassword.toString().getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(ALGORITHM + " is not available", e);
        }
    }
}
