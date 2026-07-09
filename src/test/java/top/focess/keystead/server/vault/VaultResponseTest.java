package top.focess.keystead.server.vault;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class VaultResponseTest {

    private static final Instant CREATED_AT = Instant.parse("2026-07-10T00:00:00Z");
    private static final Instant UPDATED_AT = Instant.parse("2026-07-10T00:01:00Z");
    private static final Instant BEFORE_CREATED_AT = Instant.parse("2026-07-09T23:59:59Z");

    @Test
    void rejectsBlankVaultResponseFields() {
        assertThrows(
                IllegalArgumentException.class,
                () -> response(" ", "encrypted-metadata", UPDATED_AT));
        assertThrows(IllegalArgumentException.class, () -> response("vault-a", " ", UPDATED_AT));
    }

    @Test
    void rejectsUpdatedTimeBeforeCreatedTime() {
        assertThrows(
                IllegalArgumentException.class,
                () -> response("vault-a", "encrypted-metadata", BEFORE_CREATED_AT));
    }

    private static VaultResponse response(
            String vaultId, String encryptedMetadata, Instant updatedAt) {
        return new VaultResponse(vaultId, encryptedMetadata, CREATED_AT, updatedAt);
    }
}
