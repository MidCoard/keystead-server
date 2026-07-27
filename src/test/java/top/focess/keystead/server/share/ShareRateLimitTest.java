package top.focess.keystead.server.share;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Share rate limiting: a per-owner ceiling on mint and a per-client-ip ceiling on redeem. The class
 * sets tight ceilings (2/minute each) via a dedicated property source so its Spring context is
 * isolated from the default-context share tests.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(
        properties = {
            "keystead.share.mint-rate-limit-per-minute=2",
            "keystead.share.redeem-rate-limit-per-minute=2"
        })
class ShareRateLimitTest {

    @Autowired private MockMvc mvc;

    @Test
    void mintOverLimitIsThrottled() throws Exception {
        String token = login(register("share-mint-limit"));
        mint(token);
        mint(token);
        mvc.perform(
                        post("/api/v1/shares")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"payload\":\"keystead-share:v1:third\"}"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "60"));
    }

    @Test
    void redeemOverLimitIsThrottled() throws Exception {
        String token = login(register("share-redeem-limit"));
        String code = mintNonBurning(token);
        redeem(code);
        redeem(code);
        mvc.perform(get("/api/v1/shares/{code}", code))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "60"));
    }

    private String register(String username) throws Exception {
        mvc.perform(
                        post("/api/v1/users")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        "{\"username\":\""
                                                + username
                                                + "\",\"password\":\"correct horse battery staple\"}"))
                .andExpect(status().isCreated());
        return username;
    }

    private String login(String username) throws Exception {
        MvcResult result =
                mvc.perform(
                                post("/api/v1/auth/login")
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(
                                                "{\"username\":\""
                                                        + username
                                                        + "\",\"password\":\"correct horse battery staple\"}"))
                        .andExpect(status().isOk())
                        .andReturn();
        return JsonPath.read(result.getResponse().getContentAsString(), "$.accessToken");
    }

    private void mint(String token) throws Exception {
        mvc.perform(
                        post("/api/v1/shares")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"payload\":\"keystead-share:v1:opaque\"}"))
                .andExpect(status().isCreated());
    }

    private String mintNonBurning(String token) throws Exception {
        MvcResult result =
                mvc.perform(
                                post("/api/v1/shares")
                                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(
                                                "{\"payload\":\"keystead-share:v1:nonburn\",\"burnAfterReading\":false}"))
                        .andExpect(status().isCreated())
                        .andReturn();
        return JsonPath.read(result.getResponse().getContentAsString(), "$.code");
    }

    private void redeem(String code) throws Exception {
        mvc.perform(get("/api/v1/shares/{code}", code)).andExpect(status().isOk());
    }
}
