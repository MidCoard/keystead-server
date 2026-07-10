package top.focess.keystead.server.vault;

import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.persistence.Index;
import jakarta.persistence.Table;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class VaultEntityMappingTest {

    @Test
    void vaultEntityDeclaresOwnerLookupIndex() {
        Table table = VaultEntity.class.getAnnotation(Table.class);

        assertTrue(
                Arrays.stream(table.indexes())
                        .anyMatch(
                                index ->
                                        hasNameAndColumnList(
                                                index, "idx_vaults_owner", "owner_id")));
    }

    @Test
    void vaultKeyPackageEntityDeclaresOwnerVaultLookupIndex() {
        Table table = VaultKeyPackageEntity.class.getAnnotation(Table.class);

        assertTrue(
                Arrays.stream(table.indexes())
                        .anyMatch(
                                index ->
                                        hasNameAndColumnList(
                                                index,
                                                "idx_vault_key_packages_owner_vault",
                                                "owner_id, vault_id")));
    }

    private static boolean hasNameAndColumnList(Index index, String name, String columnList) {
        return name.equals(index.name()) && columnList.equals(index.columnList());
    }
}
