package top.focess.keystead.server.record;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import org.junit.jupiter.api.Test;

class SecretTypeCatalogEntryResponseTest {

    @Test
    void rejectsDuplicateFieldNames() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new SecretTypeCatalogEntryResponse(
                                "LOGIN_PASSWORD",
                                "communication",
                                null,
                                null,
                                false,
                                null,
                                false,
                                List.of(
                                        new SecretTypeFieldCatalogResponse(
                                                "username", "SECRET", true, true),
                                        new SecretTypeFieldCatalogResponse(
                                                "username", "SECRET", false, true))));
    }
}
