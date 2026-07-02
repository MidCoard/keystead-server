package top.focess.keystead.server.identity;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
class UserDeviceApiTest {

    @Autowired private MockMvc mvc;

    @Test
    void userRegistrationCreatesBasicAuthIdentity() throws Exception {
        mvc.perform(
                        post("/api/v1/users")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "username": "auth-user",
                                          "password": "correct horse battery staple"
                                        }
                                        """))
                .andExpect(status().isCreated());

        mvc.perform(
                        get("/api/v1/devices")
                                .with(httpBasic("auth-user", "correct horse battery staple")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    void duplicateUserRegistrationIsConflict() throws Exception {
        String body =
                """
                {
                  "username": "duplicate-user",
                  "password": "correct horse battery staple"
                }
                """;

        mvc.perform(post("/api/v1/users").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated());

        mvc.perform(post("/api/v1/users").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isConflict());
    }

    @Test
    void authenticatedUserCanRegisterAndListDevicePublicKeys() throws Exception {
        registerUser("device-user");

        mvc.perform(
                        post("/api/v1/devices")
                                .with(httpBasic("device-user", "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "deviceId": "phone-1",
                                          "keyAlgorithm": "RSA_OAEP_SHA256",
                                          "publicKey": "public-key-material"
                                        }
                                        """))
                .andExpect(status().isCreated());

        mvc.perform(
                        get("/api/v1/devices")
                                .with(httpBasic("device-user", "correct horse battery staple")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].deviceId").value("phone-1"))
                .andExpect(jsonPath("$[0].keyAlgorithm").value("RSA_OAEP_SHA256"))
                .andExpect(jsonPath("$[0].publicKey").value("public-key-material"));
    }

    private void registerUser(String username) throws Exception {
        mvc.perform(
                        post("/api/v1/users")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "username": "%s",
                                          "password": "correct horse battery staple"
                                        }
                                        """
                                                .formatted(username)))
                .andExpect(status().isCreated());
    }
}
