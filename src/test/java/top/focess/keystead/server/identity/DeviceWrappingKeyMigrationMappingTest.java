package top.focess.keystead.server.identity;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import org.junit.jupiter.api.Test;

class DeviceWrappingKeyMigrationMappingTest {

    @Test
    void migrationAddsNullableDeviceWrappingKeyColumns() throws IOException {
        String migration =
                Files.readString(
                                Path.of(
                                        "src/main/resources/db/migration/V19__device_wrapping_keys.sql"))
                        .toLowerCase(Locale.ROOT)
                        .replaceAll("\\s+", " ")
                        .trim();

        assertTrue(
                migration.contains(
                        "alter table devices add column wrapping_key_algorithm varchar(64)"));
        assertTrue(migration.contains("alter table devices add column wrapping_public_key text"));
        assertFalse(migration.contains("wrapping_key_algorithm varchar(64) not null"));
        assertFalse(migration.contains("wrapping_public_key text not null"));
        assertTrue(
                migration.contains(
                        "add constraint ck_devices_wrapping_key_pair check ( (wrapping_key_algorithm is null and wrapping_public_key is null) or (wrapping_key_algorithm is not null and wrapping_public_key is not null) )"));
    }
}
