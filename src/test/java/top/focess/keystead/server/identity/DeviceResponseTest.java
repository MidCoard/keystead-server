package top.focess.keystead.server.identity;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class DeviceResponseTest {

    private static final Instant CREATED_AT = Instant.parse("2026-07-10T00:00:00Z");
    private static final Instant BEFORE_CREATED_AT = Instant.parse("2026-07-09T23:59:59Z");

    @Test
    void rejectsBlankDeviceResponseFields() {
        assertThrows(
                IllegalArgumentException.class,
                () -> response(" ", "RSA_OAEP_SHA256", "public-key", null, null, null));
        assertThrows(
                IllegalArgumentException.class,
                () -> response("device-a", " ", "public-key", null, null, null));
        assertThrows(
                IllegalArgumentException.class,
                () -> response("device-a", "RSA_OAEP_SHA256", " ", null, null, null));
    }

    @Test
    void rejectsUnsupportedDeviceKeyAlgorithm() {
        assertThrows(
                IllegalArgumentException.class,
                () -> response("device-a", "RAW_RSA", "public-key", null, null, null));
    }

    @Test
    void rejectsLifecycleMarkersBeforeCreatedTime() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        response(
                                "device-a",
                                "RSA_OAEP_SHA256",
                                "public-key",
                                BEFORE_CREATED_AT,
                                null,
                                null));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        response(
                                "device-a",
                                "RSA_OAEP_SHA256",
                                "public-key",
                                null,
                                BEFORE_CREATED_AT,
                                null));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        response(
                                "device-a",
                                "RSA_OAEP_SHA256",
                                "public-key",
                                null,
                                null,
                                BEFORE_CREATED_AT));
    }

    private static DeviceResponse response(
            String deviceId,
            String keyAlgorithm,
            String publicKey,
            Instant verifiedAt,
            Instant lastSeenAt,
            Instant revokedAt) {
        return new DeviceResponse(
                deviceId, keyAlgorithm, publicKey, CREATED_AT, verifiedAt, lastSeenAt, revokedAt);
    }
}
