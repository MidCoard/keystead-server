package top.focess.keystead.server.auth;

import static org.hamcrest.Matchers.blankOrNullString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthApiTest {

    @Autowired private MockMvc mvc;

    @Test
    void loginReturnsTokensAndBearerTokenAuthenticatesApi() throws Exception {
        register("token-alice");

        MvcResult login =
                mvc.perform(
                                post("/api/v1/auth/login")
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(
                                                """
                                                {
                                                  "username": "token-alice",
                                                  "password": "correct horse battery staple"
                                                }
                                                """))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.accessToken", not(blankOrNullString())))
                        .andExpect(jsonPath("$.refreshToken", not(blankOrNullString())))
                        .andExpect(jsonPath("$.accessTokenExpiresAt", not(blankOrNullString())))
                        .andExpect(jsonPath("$.refreshTokenExpiresAt", not(blankOrNullString())))
                        .andReturn();
        String accessToken = JsonStrings.field(login, "accessToken");

        mvc.perform(
                        put("/api/v1/vaults/token-vault")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "encryptedMetadata": "opaque-vault-metadata"
                                        }
                                        """))
                .andExpect(status().isCreated());

        mvc.perform(
                        get("/api/v1/vaults")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].vaultId").value("token-vault"));
    }

    @Test
    void refreshTokenCanRefreshThenBeRevoked() throws Exception {
        register("refresh-alice");
        String refreshToken = login("refresh-alice");

        mvc.perform(
                        post("/api/v1/auth/refresh")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(refreshBody(refreshToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken", not(blankOrNullString())))
                .andExpect(jsonPath("$.refreshToken").doesNotExist());

        mvc.perform(
                        post("/api/v1/auth/revoke")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(refreshBody(refreshToken)))
                .andExpect(status().isNoContent());

        mvc.perform(
                        post("/api/v1/auth/refresh")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(refreshBody(refreshToken)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void logoutAllRevokesAllUserRefreshTokens() throws Exception {
        register("logout-all-alice");
        MvcResult firstLogin = loginResult("logout-all-alice");
        MvcResult secondLogin = loginResult("logout-all-alice");
        String accessToken = JsonStrings.field(firstLogin, "accessToken");
        String firstRefreshToken = JsonStrings.field(firstLogin, "refreshToken");
        String secondRefreshToken = JsonStrings.field(secondLogin, "refreshToken");

        mvc.perform(
                        post("/api/v1/auth/logout-all")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isNoContent());

        mvc.perform(
                        post("/api/v1/auth/refresh")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(refreshBody(firstRefreshToken)))
                .andExpect(status().isUnauthorized());
        mvc.perform(
                        post("/api/v1/auth/refresh")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(refreshBody(secondRefreshToken)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void loginFailureIsGeneric() throws Exception {
        register("failed-login-alice");

        mvc.perform(
                        post("/api/v1/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "username": "failed-login-alice",
                                          "password": "wrong password value"
                                        }
                                        """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Authentication failed"));
    }

    private void register(String username) throws Exception {
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

    private String login(String username) throws Exception {
        return JsonStrings.field(loginResult(username), "refreshToken");
    }

    private MvcResult loginResult(String username) throws Exception {
        return mvc.perform(
                        post("/api/v1/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "username": "%s",
                                          "password": "correct horse battery staple"
                                        }
                                        """
                                                .formatted(username)))
                .andExpect(status().isOk())
                .andReturn();
    }

    private static String refreshBody(String refreshToken) {
        return """
                {
                  "refreshToken": "%s"
                }
                """
                .formatted(refreshToken);
    }
}
