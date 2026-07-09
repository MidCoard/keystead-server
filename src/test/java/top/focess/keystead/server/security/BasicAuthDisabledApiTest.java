package top.focess.keystead.server.security;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = "keystead.security.basic-auth-enabled=false")
@AutoConfigureMockMvc
@ActiveProfiles("test")
class BasicAuthDisabledApiTest {

    @Autowired private MockMvc mvc;

    @Test
    void basicAuthIsRejectedWhenDisabled() throws Exception {
        mvc.perform(
                        post("/api/v1/users")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "username": "basic-disabled-alice",
                                          "password": "correct horse battery staple"
                                        }
                                        """))
                .andExpect(status().isCreated());

        mvc.perform(
                        get("/api/v1/vaults")
                                .with(
                                        httpBasic(
                                                "basic-disabled-alice",
                                                "correct horse battery staple")))
                .andExpect(status().isUnauthorized());
    }
}
