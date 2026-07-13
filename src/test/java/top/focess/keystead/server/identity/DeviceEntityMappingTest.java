package top.focess.keystead.server.identity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.persistence.Index;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class DeviceEntityMappingTest {

    @Test
    void deviceEntityDeclaresOwnerLookupIndex() {
        Table table = DeviceEntity.class.getAnnotation(Table.class);

        assertTrue(
                Arrays.stream(table.indexes())
                        .anyMatch(
                                index ->
                                        hasNameAndColumnList(
                                                index, "idx_devices_owner", "owner_id")));
    }

    @Test
    void deviceChallengeEntityDeclaresOwnerDeviceLookupIndex() {
        Table table = DeviceChallengeEntity.class.getAnnotation(Table.class);

        assertTrue(
                Arrays.stream(table.indexes())
                        .anyMatch(
                                index ->
                                        hasNameAndColumnList(
                                                index,
                                                "idx_device_challenges_owner_device",
                                                "owner_id, device_id")));
    }

    @Test
    void deviceEntityRoundTripsSeparateProofAndWrappingPublicKeys() {
        StoredDevice device =
                new StoredDevice(
                        "owner-a",
                        "device-a",
                        "ED25519",
                        "proof-public-key",
                        "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
                        "wrapping-public-key",
                        Instant.parse("2026-07-12T00:00:00Z"),
                        null,
                        null,
                        null);

        StoredDevice roundTripped = DeviceEntity.from(device).toStored();

        assertEquals(device, roundTripped);
    }

    @Test
    void deviceEntityRoundTripsLegacyProofOnlyRow() {
        StoredDevice device =
                new StoredDevice(
                        "owner-legacy",
                        "device-legacy",
                        "ED25519",
                        "proof-public-key",
                        Instant.parse("2026-07-12T00:00:00Z"),
                        null,
                        null,
                        null);

        StoredDevice roundTripped = DeviceEntity.from(device).toStored();

        assertNull(roundTripped.wrappingKeyAlgorithm());
        assertNull(roundTripped.wrappingPublicKey());
    }

    private static boolean hasNameAndColumnList(Index index, String name, String columnList) {
        return name.equals(index.name()) && columnList.equals(index.columnList());
    }
}
