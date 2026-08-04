package top.focess.keystead.server.auth;

import static org.hamcrest.Matchers.blankOrNullString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
    void loginReturnsAccountTokensAndBearerTokenAuthenticatesPersonalStream() throws Exception {
        register("token-alice");

        MvcResult login = loginResult("token-alice");
        String accessToken = JsonStrings.field(login, "accessToken");

        mvc.perform(
                        get("/api/v1/vault/records")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records").isArray());
    }

    @Test
    void refreshTokenRotatesAndRejectsReplay() throws Exception {
        register("refresh-alice");
        String refreshToken = JsonStrings.field(loginResult("refresh-alice"), "refreshToken");

        MvcResult refreshed =
                mvc.perform(
                                post("/api/v1/auth/refresh")
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(refreshBody(refreshToken)))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.accessToken", not(blankOrNullString())))
                        .andExpect(jsonPath("$.refreshToken", not(blankOrNullString())))
                        .andReturn();
        String replacementToken = JsonStrings.field(refreshed, "refreshToken");

        mvc.perform(
                        post("/api/v1/auth/refresh")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(refreshBody(refreshToken)))
                .andExpect(status().isUnauthorized());
        mvc.perform(
                        post("/api/v1/auth/refresh")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(refreshBody(replacementToken)))
                .andExpect(status().isOk());
    }

    @Test
    void logoutAllRevokesRefreshAndAccessTokens() throws Exception {
        register("logout-alice");
        MvcResult first = loginResult("logout-alice");
        MvcResult second = loginResult("logout-alice");
        String logoutToken = JsonStrings.field(first, "accessToken");
        String refreshToken = JsonStrings.field(second, "refreshToken");
        String staleAccessToken = JsonStrings.field(second, "accessToken");

        mvc.perform(
                        post("/api/v1/auth/logout-all")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + logoutToken))
                .andExpect(status().isNoContent());
        mvc.perform(
                        post("/api/v1/auth/refresh")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(refreshBody(refreshToken)))
                .andExpect(status().isUnauthorized());
        mvc.perform(
                        get("/api/v1/vault/records")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + staleAccessToken))
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
                .andExpect(jsonPath("$.accessToken", not(blankOrNullString())))
                .andExpect(jsonPath("$.refreshToken", not(blankOrNullString())))
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
