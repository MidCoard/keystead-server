package top.focess.keystead.server.identity;

import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.persistence.Index;
import jakarta.persistence.Table;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class DeviceVaultSyncCursorEntityMappingTest {

    @Test
    void entityDeclaresVaultAcknowledgementRevisionIndex() {
        Table table = DeviceVaultSyncCursorEntity.class.getAnnotation(Table.class);

        assertTrue(
                Arrays.stream(table.indexes())
                        .anyMatch(
                                index ->
                                        hasNameAndColumnList(
                                                index,
                                                "idx_device_vault_sync_cursors_owner_vault_revision",
                                                "owner_id, vault_id, pulled_revision")));
    }

    private static boolean hasNameAndColumnList(Index index, String name, String columnList) {
        return name.equals(index.name()) && columnList.equals(index.columnList());
    }
}
