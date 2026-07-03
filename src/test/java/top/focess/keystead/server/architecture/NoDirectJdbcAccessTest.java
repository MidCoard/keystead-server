package top.focess.keystead.server.architecture;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class NoDirectJdbcAccessTest {

    @Test
    void productionCodeDoesNotUseSpringJdbcDirectly() throws IOException {
        List<String> offenders =
                Files.walk(Path.of("src/main/java"))
                        .filter(path -> path.toString().endsWith(".java"))
                        .filter(
                                path -> {
                                    try {
                                        String source = Files.readString(path);
                                        return source.contains("org.springframework.jdbc")
                                                || source.contains("JdbcTemplate");
                                    } catch (IOException e) {
                                        throw new IllegalStateException(e);
                                    }
                                })
                        .map(Path::toString)
                        .sorted()
                        .toList();

        assertEquals(List.of(), offenders);
    }

    @Test
    void buildUsesSpringDataJpaInsteadOfSpringDataJdbc() throws IOException {
        String build = Files.readString(Path.of("build.gradle.kts"));

        assertEquals(false, build.contains("spring-boot-starter-data-jdbc"));
        assertEquals(true, build.contains("spring-boot-starter-data-jpa"));
    }
}
