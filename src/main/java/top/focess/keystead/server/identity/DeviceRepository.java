package top.focess.keystead.server.identity;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
class DeviceRepository {

    private final JdbcTemplate jdbc;

    DeviceRepository(@NonNull JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @NonNull List<StoredDevice> list(@NonNull String ownerId) {
        return jdbc.query(
                """
                select owner_id, device_id, key_algorithm, public_key, created_at
                  from devices
                 where owner_id = ?
                 order by device_id
                """,
                this::map,
                ownerId);
    }

    void upsert(@NonNull StoredDevice device) {
        int updated =
                jdbc.update(
                        """
                        update devices
                           set key_algorithm = ?, public_key = ?
                         where owner_id = ? and device_id = ?
                        """,
                        device.keyAlgorithm(),
                        device.publicKey(),
                        device.ownerId(),
                        device.deviceId());
        if (updated > 0) {
            return;
        }
        jdbc.update(
                """
                insert into devices (owner_id, device_id, key_algorithm, public_key, created_at)
                values (?, ?, ?, ?, ?)
                """,
                device.ownerId(),
                device.deviceId(),
                device.keyAlgorithm(),
                device.publicKey(),
                Timestamp.from(device.createdAt()));
    }

    private @NonNull StoredDevice map(@NonNull ResultSet resultSet, int row) throws SQLException {
        return new StoredDevice(
                resultSet.getString("owner_id"),
                resultSet.getString("device_id"),
                resultSet.getString("key_algorithm"),
                resultSet.getString("public_key"),
                resultSet.getTimestamp("created_at").toInstant());
    }
}
