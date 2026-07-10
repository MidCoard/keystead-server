package top.focess.keystead.server.record;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.Test;
import top.focess.keystead.model.SecretTypeCatalog;
import top.focess.keystead.model.SecretTypeCatalogEntry;

class SecretTypeCatalogCoreBridgeTest {

    @Test
    void serverCatalogRowsAreProjectedFromCoreCatalogRows() {
        List<SecretTypeCatalogEntryResponse> serverRows = RecordSecretTypes.catalog();
        List<SecretTypeCatalogEntry> coreRows = SecretTypeCatalog.defaults();

        assertEquals(coreRows.size(), serverRows.size());
        for (int i = 0; i < coreRows.size(); i++) {
            SecretTypeCatalogEntry core = coreRows.get(i);
            SecretTypeCatalogEntryResponse server = serverRows.get(i);

            assertEquals(core.type().name(), server.type());
            assertEquals(core.defaultCategory(), server.defaultCategory());
            assertEquals(core.defaultProvider(), server.defaultProvider());
            assertEquals(core.defaultSoftware(), server.defaultSoftware());
            assertEquals(core.allowsCustomFields(), server.allowsCustomFields());
            assertEquals(
                    core.customFieldType() == null ? null : core.customFieldType().name(),
                    server.customFieldType());
            assertEquals(core.customFieldsRevealable(), server.customFieldsRevealable());
            assertEquals(core.fields().size(), server.fields().size());
        }
    }
}
