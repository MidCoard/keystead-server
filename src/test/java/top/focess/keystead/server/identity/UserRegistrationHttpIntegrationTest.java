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

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class UserRegistrationHttpIntegrationTest {

    @LocalServerPort private int port;

    @Test
    void invalidRegistrationKeepsBadRequestStatusThroughContainerErrorDispatch() throws Exception {
        // Below the @Size(min = 12) minimum on UserRegistrationRequest.password.
        String username = "http-password-limit-" + UUID.randomUUID();
        String body =
                """
                {"username":"%s","password":"%s"}
                """
                        .formatted(username, "a".repeat(11))
                        .trim();
        HttpRequest request =
                HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/api/v1/users"))
                        .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build();

        HttpResponse<Void> response =
                HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding());

        assertEquals(400, response.statusCode());
    }

    @Test
    void longPasswordRegistrationIsAccepted() throws Exception {
        // Passwords beyond bcrypt's 72-byte limit must work: the server
        // pre-hashes credentials with SHA-256 before bcrypt.
        String username = "http-long-password-" + UUID.randomUUID();
        String body =
                """
                {"username":"%s","password":"%s"}
                """
                        .formatted(username, "a".repeat(73))
                        .trim();
        HttpRequest request =
                HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/api/v1/users"))
                        .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build();

        HttpResponse<Void> response =
                HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding());

        assertEquals(201, response.statusCode());
    }
}
