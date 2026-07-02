package top.focess.keystead.server.identity;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
class UserRepository {

    private final JdbcTemplate jdbc;

    UserRepository(@NonNull JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @NonNull Optional<StoredUser> find(@NonNull String username) {
        return jdbc
                .query(
                        """
                        select username, password_hash, created_at, updated_at
                          from app_users
                         where username = ?
                        """,
                        this::map,
                        username)
                .stream()
                .findFirst();
    }

    boolean exists(@NonNull String username) {
        Integer count =
                jdbc.queryForObject(
                        "select count(*) from app_users where username = ?",
                        Integer.class,
                        username);
        return count != null && count > 0;
    }

    void insert(@NonNull StoredUser user) {
        jdbc.update(
                """
                insert into app_users (username, password_hash, created_at, updated_at)
                values (?, ?, ?, ?)
                """,
                user.username(),
                user.passwordHash(),
                Timestamp.from(user.createdAt()),
                Timestamp.from(user.updatedAt()));
    }

    private @NonNull StoredUser map(@NonNull ResultSet resultSet, int row) throws SQLException {
        return new StoredUser(
                resultSet.getString("username"),
                resultSet.getString("password_hash"),
                resultSet.getTimestamp("created_at").toInstant(),
                resultSet.getTimestamp("updated_at").toInstant());
    }
}
