package top.focess.keystead.server.share;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Hosts opaque share strings and resolves short codes back to them. The server never creates,
 * inspects, or opens a share: the payload is treated as an opaque blob, and the passphrase never
 * leaves the client. Shares expire and optionally burn after the first read.
 */
@Service
class ShareService {

    static final int MAX_PAYLOAD_LENGTH = 2 * 1024 * 1024;
    private static final int CODE_BYTES = 9;
    private static final int MAX_CODE_ATTEMPTS = 8;

    private final ShareRepository shares;
    private final ShareRateLimiter rateLimiter;
    private final Clock clock;
    private final Validator validator;
    private final ShareProperties properties;
    private final SecureRandom secureRandom = new SecureRandom();

    ShareService(
            @NonNull ShareRepository shares,
            @NonNull ShareRateLimiter rateLimiter,
            @NonNull Clock clock,
            @NonNull Validator validator,
            @NonNull ShareProperties properties) {
        this.shares = shares;
        this.rateLimiter = rateLimiter;
        this.clock = clock;
        this.validator = validator;
        this.properties = properties;
    }

    @Transactional
    @NonNull MintShareResponse mint(@NonNull String ownerId, @NonNull MintShareRequest request) {
        if (!rateLimiter.tryAcquireMint(ownerId)) {
            throw new ShareRateLimitedException();
        }
        validate(request);
        String payload = request.payload();
        if (payload.length() > MAX_PAYLOAD_LENGTH) {
            throw new InvalidShareRequestException("payload exceeds the maximum length");
        }
        Instant now = clock.instant();
        Instant expiresAt =
                request.expiresAt() != null
                        ? request.expiresAt()
                        : now.plus(properties.defaultTtl());
        if (!expiresAt.isAfter(now)) {
            throw new InvalidShareRequestException("expiry must be in the future");
        }
        if (expiresAt.isAfter(now.plus(properties.maxTtl()))) {
            throw new InvalidShareRequestException("expiry exceeds the maximum TTL");
        }
        boolean burnAfterReading =
                request.burnAfterReading() != null ? request.burnAfterReading() : true;
        String code = newCode();
        shares.persist(new Share(code, ownerId, payload, burnAfterReading, expiresAt, now));
        return new MintShareResponse(code, expiresAt);
    }

    @Transactional
    @NonNull RedeemShareResponse redeem(@NonNull String code, @NonNull String clientIp) {
        if (!rateLimiter.tryAcquireRedeem(clientIp)) {
            throw new ShareRateLimitedException();
        }
        Instant now = clock.instant();
        Share share =
                shares.find(code)
                        .orElseThrow(() -> new ShareNotFoundException("share does not exist"));
        if (!share.expiresAt().isAfter(now)) {
            // Expired: purge lazily and report. The atomic delete collapses concurrent
            // expired-redeems onto a single row removal.
            shares.deleteByCode(code);
            throw new ShareExpiredException("share has expired");
        }
        if (share.burnAfterReading()) {
            // Atomically burn: only the first concurrent redeemer wins the race. The loser sees
            // zero rows affected (another transaction already deleted it) and gets a 404, so the
            // burn-after-reading guarantee holds under contention.
            if (shares.deleteByCode(code) == 0) {
                throw new ShareNotFoundException("share does not exist");
            }
        }
        return new RedeemShareResponse(share.payload());
    }

    @Transactional(readOnly = true)
    @NonNull List<ShareSummary> list(@NonNull String ownerId) {
        Instant now = clock.instant();
        return shares.listByOwner(ownerId).stream()
                .filter(share -> share.expiresAt().isAfter(now))
                .map(ShareService::toSummary)
                .toList();
    }

    @Transactional
    void delete(@NonNull String ownerId, @NonNull String code) {
        if (shares.deleteByCodeAndOwner(code, ownerId) == 0) {
            throw new ShareNotFoundException("share does not exist");
        }
    }

    /**
     * Periodically purges expired shares so the table does not grow without bound. Expired rows are
     * also purged lazily on redeem, but a share that is never redeemed would otherwise persist
     * forever; this sweep (backed by {@code idx_shares_expires_at}) reclaims them.
     */
    @Transactional
    @Scheduled(fixedDelayString = "${keystead.share.expiry-sweep-millis:600000}")
    void purgeExpiredShares() {
        shares.deleteExpired(clock.instant());
    }

    private void validate(@NonNull Object request) {
        Set<? extends ConstraintViolation<?>> violations = validator.validate(request);
        if (!violations.isEmpty()) {
            throw new InvalidShareRequestException(
                    violations.iterator().next().getPropertyPath() + " is invalid");
        }
    }

    private static @NonNull ShareSummary toSummary(@NonNull Share share) {
        return new ShareSummary(
                share.code(), share.createdAt(), share.expiresAt(), share.burnAfterReading());
    }

    private @NonNull String newCode() {
        for (int attempt = 0; attempt < MAX_CODE_ATTEMPTS; attempt++) {
            byte[] bytes = new byte[CODE_BYTES];
            secureRandom.nextBytes(bytes);
            String code = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
            if (shares.find(code).isEmpty()) {
                return code;
            }
        }
        throw new IllegalStateException("Could not allocate a unique share code");
    }
}
