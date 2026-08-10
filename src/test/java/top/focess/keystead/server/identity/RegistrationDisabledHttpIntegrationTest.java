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

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "keystead.registration.enabled=false")
@ActiveProfiles("test")
class RegistrationDisabledHttpIntegrationTest {

    @LocalServerPort private int port;

    @Test
    void registrationRejectedWithForbiddenWhenDisabled() throws Exception {
        String username = "reg-disabled-" + UUID.randomUUID();
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

        HttpResponse<Void> response =
                HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding());

        assertEquals(403, response.statusCode());
    }
}
