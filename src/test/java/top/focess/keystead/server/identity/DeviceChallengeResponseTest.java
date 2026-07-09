package top.focess.keystead.server.identity;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class DeviceChallengeResponseTest {

    private static final Instant EXPIRES_AT = Instant.parse("2026-07-10T00:05:00Z");

    @Test
    void rejectsBlankChallengeResponseFields() {
        assertThrows(IllegalArgumentException.class, () -> response(" ", "challenge-a", "nonce-a"));
        assertThrows(IllegalArgumentException.class, () -> response("device-a", " ", "nonce-a"));
        assertThrows(
                IllegalArgumentException.class, () -> response("device-a", "challenge-a", " "));
    }

    private static DeviceChallengeResponse response(
            String deviceId, String challengeId, String nonce) {
        return new DeviceChallengeResponse(deviceId, challengeId, nonce, EXPIRES_AT);
    }
}
