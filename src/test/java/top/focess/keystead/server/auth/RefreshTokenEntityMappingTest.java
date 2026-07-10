package top.focess.keystead.server.auth;

import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.persistence.Index;
import jakarta.persistence.Table;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class RefreshTokenEntityMappingTest {

    @Test
    void refreshTokenEntityDeclaresUsernameLookupIndex() {
        Table table = RefreshTokenEntity.class.getAnnotation(Table.class);

        assertTrue(
                Arrays.stream(table.indexes())
                        .anyMatch(
                                index ->
                                        hasNameAndColumnList(
                                                index,
                                                "idx_auth_refresh_tokens_username",
                                                "username")));
    }

    private static boolean hasNameAndColumnList(Index index, String name, String columnList) {
        return name.equals(index.name()) && columnList.equals(index.columnList());
    }
}
