package top.focess.keystead.server.audit;

import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.persistence.Index;
import jakarta.persistence.Table;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class AuditEventEntityMappingTest {

    @Test
    void entityDeclaresAuditReadIndexes() {
        Table table = AuditEventEntity.class.getAnnotation(Table.class);

        assertTrue(
                Arrays.stream(table.indexes())
                        .anyMatch(
                                index ->
                                        hasNameAndColumnList(
                                                index,
                                                "idx_audit_events_owner_created",
                                                "owner_id, created_at")));
        assertTrue(
                Arrays.stream(table.indexes())
                        .anyMatch(
                                index ->
                                        hasNameAndColumnList(
                                                index,
                                                "idx_audit_events_owner_vault",
                                                "owner_id, vault_id")));
    }

    private static boolean hasNameAndColumnList(Index index, String name, String columnList) {
        return name.equals(index.name()) && columnList.equals(index.columnList());
    }
}
