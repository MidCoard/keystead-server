package top.focess.keystead.server.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@ActiveProfiles("test")
class RefreshTokenRepositoryTest {

    private static final Instant CREATED_AT = Instant.parse("2026-07-09T00:00:00Z");
    private static final Instant LAST_USED_AT = Instant.parse("2026-07-09T00:01:00Z");
    private static final Instant EXPIRES_AT = Instant.parse("2026-08-08T00:00:00Z");

    @Autowired private RefreshTokenRepository refreshTokens;

    @Test
    void databaseInsertRejectsDuplicateRefreshTokenHash() {
        refreshTokens.insert(token("refresh-token-hash-a", "alice"));

        assertThrows(
                DataIntegrityViolationException.class,
                () -> refreshTokens.insert(token("refresh-token-hash-a", "bob")));
    }

    @Test
    @Transactional
    void activeTokenCanBeConsumedOnlyOnce() {
        StoredRefreshToken token = token("refresh-token-hash-consume", "consume-alice");
        refreshTokens.insert(token);

        assertEquals(
                1,
                refreshTokens.consumeActive(
                        token.tokenHash(),
                        LAST_USED_AT.plusSeconds(1),
                        LAST_USED_AT.plusSeconds(1)));
        assertEquals(
                0,
                refreshTokens.consumeActive(
                        token.tokenHash(),
                        LAST_USED_AT.plusSeconds(2),
                        LAST_USED_AT.plusSeconds(2)));
    }

    private static StoredRefreshToken token(String tokenHash, String username) {
        return new StoredRefreshToken(
                tokenHash, username, "device-a", EXPIRES_AT, null, CREATED_AT, LAST_USED_AT);
    }
}
