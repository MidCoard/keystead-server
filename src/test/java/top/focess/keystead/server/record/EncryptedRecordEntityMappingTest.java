package top.focess.keystead.server.record;

import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class EncryptedRecordEntityMappingTest {

    @Test
    void entityDeclaresVaultWideRevisionUniquenessAndSyncIndexes() {
        Table table = EncryptedRecordEntity.class.getAnnotation(Table.class);

        assertTrue(
                Arrays.stream(table.uniqueConstraints())
                        .anyMatch(
                                constraint ->
                                        hasNameAndColumns(
                                                constraint,
                                                "uq_encrypted_records_owner_vault_revision",
                                                "owner_id",
                                                "vault_id",
                                                "revision")));
        assertTrue(
                Arrays.stream(table.indexes())
                        .anyMatch(
                                index ->
                                        hasNameAndColumnList(
                                                index,
                                                "idx_encrypted_records_sync_page",
                                                "owner_id, vault_id, revision, secret_id")));
    }

    private static boolean hasNameAndColumns(
            UniqueConstraint constraint, String name, String... columns) {
        return name.equals(constraint.name()) && Arrays.equals(columns, constraint.columnNames());
    }

    private static boolean hasNameAndColumnList(Index index, String name, String columnList) {
        return name.equals(index.name()) && columnList.equals(index.columnList());
    }
}
