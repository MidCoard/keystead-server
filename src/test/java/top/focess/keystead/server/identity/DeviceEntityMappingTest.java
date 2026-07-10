package top.focess.keystead.server.identity;

import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.persistence.Index;
import jakarta.persistence.Table;
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

    private static boolean hasNameAndColumnList(Index index, String name, String columnList) {
        return name.equals(index.name()) && columnList.equals(index.columnList());
    }
}
