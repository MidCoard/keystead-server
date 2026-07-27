package top.focess.keystead.server.share;

import static org.hamcrest.Matchers.blankOrNullString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import java.time.Duration;
import java.time.Instant;
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
class ShareApiTest {

    @Autowired private MockMvc mvc;

    @Test
    void mintAndRedeemRoundTrip() throws Exception {
        String token = login(register("share-alice"));
        String payload = "keystead-share:v1:opaque-blob";
        MvcResult mint =
                mvc.perform(
                                post("/api/v1/shares")
                                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(payloadBody(payload, null, null)))
                        .andExpect(status().isCreated())
                        .andExpect(jsonPath("$.code", not(blankOrNullString())))
                        .andExpect(jsonPath("$.expiresAt", not(blankOrNullString())))
                        .andReturn();
        String code = JsonPath.read(mint.getResponse().getContentAsString(), "$.code");

        mvc.perform(get("/api/v1/shares/{code}", code))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.payload").value(payload));
    }

    @Test
    void redeemBurnsAfterReadingByDefault() throws Exception {
        String token = login(register("share-burn"));
        String code = mint(token, "keystead-share:v1:burn", null, null);

        mvc.perform(get("/api/v1/shares/{code}", code))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.payload").value("keystead-share:v1:burn"));
        mvc.perform(get("/api/v1/shares/{code}", code)).andExpect(status().isNotFound());
    }

    @Test
    void redeemPersistsNonBurningShare() throws Exception {
        String token = login(register("share-nonburn"));
        String code = mint(token, "keystead-share:v1:nonburn", null, false);

        mvc.perform(get("/api/v1/shares/{code}", code))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.payload").value("keystead-share:v1:nonburn"));
        mvc.perform(get("/api/v1/shares/{code}", code))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.payload").value("keystead-share:v1:nonburn"));
    }

    @Test
    void redeemUnknownShareReturnsNotFound() throws Exception {
        mvc.perform(get("/api/v1/shares/{code}", "missing-code")).andExpect(status().isNotFound());
    }

    @Test
    void listReturnsOwnersSharesWithoutPayload() throws Exception {
        String token = login(register("share-list"));
        String code = mint(token, "keystead-share:v1:list", null, false);

        mvc.perform(get("/api/v1/shares").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].code").value(code))
                .andExpect(jsonPath("$[0].createdAt", not(blankOrNullString())))
                .andExpect(jsonPath("$[0].expiresAt", not(blankOrNullString())))
                .andExpect(jsonPath("$[0].burnAfterReading").value(false))
                .andExpect(jsonPath("$[0].payload").doesNotExist());
    }

    @Test
    void ownerDeletesShare() throws Exception {
        String token = login(register("share-delete"));
        String code = mint(token, "keystead-share:v1:delete", null, null);

        mvc.perform(
                        delete("/api/v1/shares/{code}", code)
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isNoContent());
        mvc.perform(get("/api/v1/shares/{code}", code)).andExpect(status().isNotFound());
    }

    @Test
    void nonOwnerDeleteReturnsNotFound() throws Exception {
        String alice = login(register("share-owner"));
        String bob = login(register("share-intruder"));
        String code = mint(alice, "keystead-share:v1:guarded", null, false);

        mvc.perform(
                        delete("/api/v1/shares/{code}", code)
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + bob))
                .andExpect(status().isNotFound());
        mvc.perform(get("/api/v1/shares/{code}", code))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.payload").value("keystead-share:v1:guarded"));
    }

    @Test
    void mintRejectsBlankPayload() throws Exception {
        String token = login(register("share-blank"));
        mvc.perform(
                        post("/api/v1/shares")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(payloadBody("", null, null)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void mintRejectsPastExpiry() throws Exception {
        String token = login(register("share-past"));
        mvc.perform(
                        post("/api/v1/shares")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        payloadBody(
                                                "keystead-share:v1:past",
                                                Instant.parse("2020-01-01T00:00:00Z"),
                                                null)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void mintRejectsExpiryBeyondMaxTtl() throws Exception {
        String token = login(register("share-maxttl"));
        Instant beyond = Instant.now().plus(Duration.ofDays(31));
        mvc.perform(
                        post("/api/v1/shares")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(payloadBody("keystead-share:v1:far", beyond, null)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void mintRejectsMalformedExpiry() throws Exception {
        String token = login(register("share-malformed"));
        mvc.perform(
                        post("/api/v1/shares")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        "{\"payload\":\"keystead-share:v1:x\",\"expiresAt\":\"not-a-date\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void redeemMalformedCodeReturnsBadRequest() throws Exception {
        String tooLong = "a".repeat(100);
        mvc.perform(get("/api/v1/shares/{code}", tooLong)).andExpect(status().isBadRequest());
    }

    private String register(String username) throws Exception {
        mvc.perform(
                        post("/api/v1/users")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                {"username":"%s","password":"correct horse battery staple"}
                                """
                                                .formatted(username)))
                .andExpect(status().isCreated());
        return username;
    }

    private String login(String username) throws Exception {
        MvcResult result =
                mvc.perform(
                                post("/api/v1/auth/login")
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(
                                                """
                                        {"username":"%s","password":"correct horse battery staple"}
                                        """
                                                        .formatted(username)))
                        .andExpect(status().isOk())
                        .andReturn();
        return JsonPath.read(result.getResponse().getContentAsString(), "$.accessToken");
    }

    private String mint(String token, String payload, Instant expiresAt, Boolean burnAfterReading)
            throws Exception {
        MvcResult result =
                mvc.perform(
                                post("/api/v1/shares")
                                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(payloadBody(payload, expiresAt, burnAfterReading)))
                        .andExpect(status().isCreated())
                        .andReturn();
        return JsonPath.read(result.getResponse().getContentAsString(), "$.code");
    }

    private static String payloadBody(String payload, Instant expiresAt, Boolean burnAfterReading) {
        StringBuilder body = new StringBuilder("{\"payload\":\"").append(payload).append("\"");
        if (expiresAt != null) {
            body.append(",\"expiresAt\":\"").append(expiresAt).append("\"");
        }
        if (burnAfterReading != null) {
            body.append(",\"burnAfterReading\":").append(burnAfterReading);
        }
        return body.append("}").toString();
    }
}
