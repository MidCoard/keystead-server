package top.focess.keystead.server.identity;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;

/**
 * Verifies the {@code keystead.registration.max-users} cap. Uses a dedicated in-memory database
 * (distinct from the shared {@code keystead} test database, whose user count is polluted by other
 * tests via {@code DB_CLOSE_DELAY=-1}) so the cap is evaluated against a known-zero starting count.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
            "keystead.registration.max-users=1",
            "spring.datasource.url=jdbc:h2:mem:keystead-regcap;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1"
        })
@ActiveProfiles("test")
class RegistrationUserCapHttpIntegrationTest {

    @LocalServerPort private int port;

    @Test
    void registrationClosesOnceUserCapReached() throws Exception {
        // First registration fills the single-user cap.
        HttpResponse<Void> firstResponse = register("reg-cap-first-" + UUID.randomUUID());
        assertEquals(201, firstResponse.statusCode());

        // A second registration is now rejected with 403.
        HttpResponse<Void> secondResponse = register("reg-cap-second-" + UUID.randomUUID());
        assertEquals(403, secondResponse.statusCode());
    }

    private HttpResponse<Void> register(String username) throws Exception {
        String body =
                """
                {"username":"%s","password":"%s"}
                """
                        .formatted(username, "a".repeat(12))
                        .trim();
        HttpRequest request =
                HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/api/v1/users"))
                        .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding());
    }
}
