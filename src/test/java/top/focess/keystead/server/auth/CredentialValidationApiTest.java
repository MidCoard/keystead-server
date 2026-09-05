package top.focess.keystead.server.auth;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class CredentialValidationApiTest {
    @Autowired private MockMvc mvc;

    @Test
    void passwordAtTheFormerLoginLimitCanRegisterAndLogIn() throws Exception {
        assertRegistrationAndLogin(1024);
    }

    @Test
    void previouslyAcceptedRegistrationPasswordBeyondTheLoginLimitCanLogIn() throws Exception {
        // Registration already accepted these credentials before the fix. Login must continue
        // accepting their existing password hashes, as well as newly registered passwords.
        assertRegistrationAndLogin(1025);
    }

    private void assertRegistrationAndLogin(int length) throws Exception {
        String body =
                "{\"username\":\"%s\",\"password\":\"%s\"}"
                        .formatted("long-password-" + UUID.randomUUID(), "x".repeat(length));
        mvc.perform(post("/api/v1/users").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated());
        mvc.perform(
                        post("/api/v1/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                .andExpect(status().isOk());
    }
}
