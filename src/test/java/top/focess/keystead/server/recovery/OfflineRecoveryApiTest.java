package top.focess.keystead.server.recovery;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.JsonPath;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class OfflineRecoveryApiTest {

    private static final String PASSWORD = "correct horse battery staple";
    private static final String CREDENTIAL = "offline-derived-recovery-credential";

    @Autowired private MockMvc mvc;
    @Autowired private EntityManager entityManager;
    @Autowired private PlatformTransactionManager transactionManager;

    private final ObjectMapper json = new ObjectMapper();

    @Test
    void knownAndUnknownAccountsReceiveTheSamePublicChallengeShape() throws Exception {
        String username = "offline-known-alice";
        registerUser(username);
        String enrollmentId = createActiveEnrollment(username);

        String known = challenge(username, enrollmentId, 1L);
        String unknown = challenge("offline-unknown-alice", "unknown-enrollment", 99L);
        Map<String, Object> knownBody =
                json.readValue(known, new TypeReference<Map<String, Object>>() {});
        Map<String, Object> unknownBody =
                json.readValue(unknown, new TypeReference<Map<String, Object>>() {});

        assertEquals(knownBody.keySet(), unknownBody.keySet());
        assertEquals(2, knownBody.size());
        assertTrue(knownBody.containsKey("challengeId"));
        assertTrue(knownBody.containsKey("expiresAt"));
        assertNotEquals(knownBody.get("challengeId"), unknownBody.get("challengeId"));
    }

    @Test
    void validCredentialCreatesOnlyHashedRestrictedSessionAndReadsScopedMaterial()
            throws Exception {
        String username = "offline-success-alice";
        registerUser(username);
        String enrollmentId = createActiveEnrollment(username);
        String challengeId = JsonPath.read(challenge(username, enrollmentId, 1L), "$.challengeId");

        String sessionJson = verify(challengeId, CREDENTIAL, 200);
        String token = JsonPath.read(sessionJson, "$.token");
        assertFalse(token.isBlank());
        assertFalse(sessionJson.contains(CREDENTIAL));

        String storedHash =
                transaction(
                        () ->
                                entityManager
                                        .createQuery(
                                                "select s.tokenHash from RecoverySessionEntity s where s.username = :username",
                                                String.class)
                                        .setParameter("username", username)
                                        .getSingleResult());
        assertNotEquals(token, storedHash);
        assertFalse(databaseContainsText(token));

        mvc.perform(
                        get("/api/v1/auth/recovery/material")
                                .header(HttpHeaders.AUTHORIZATION, "Recovery " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enrollmentId").value(enrollmentId))
                .andExpect(jsonPath("$.generation").value(1))
                .andExpect(
                        jsonPath("$.encryptedPrivateKey")
                                .value("opaque-encrypted-recovery-private-key"))
                .andExpect(jsonPath("$.vaultPackages").isArray());

        mvc.perform(get("/api/v1/auth/recovery/material").with(httpBasic(username, PASSWORD)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void wrongOrUnknownCredentialUsesGenericFailureAndStopsAtFiveAttempts() throws Exception {
        String username = "offline-attempt-alice";
        registerUser(username);
        String enrollmentId = createActiveEnrollment(username);
        String challengeId = JsonPath.read(challenge(username, enrollmentId, 1L), "$.challengeId");

        for (int attempt = 0; attempt < 6; attempt++) {
            verify(challengeId, "wrong-credential", 401);
        }
        assertEquals(5, challengeAttempts(challengeId));
        verify(challengeId, CREDENTIAL, 401);
        assertEquals(0L, sessionCount(username));

        String unknownId =
                JsonPath.read(
                        challenge("offline-missing-user", "missing-enrollment", 1L),
                        "$.challengeId");
        String unknownFailure = verify(unknownId, CREDENTIAL, 401);
        assertFalse(unknownFailure.contains("user"));
        assertFalse(unknownFailure.contains("enrollment"));
        assertFalse(unknownFailure.contains(CREDENTIAL));
    }

    @Test
    void challengesAndSessionsExpireAndSuccessfulChallengeIsSingleUse() throws Exception {
        String username = "offline-expiry-alice";
        registerUser(username);
        String enrollmentId = createActiveEnrollment(username);

        String expiredChallenge =
                JsonPath.read(challenge(username, enrollmentId, 1L), "$.challengeId");
        transaction(
                () -> {
                    entityManager
                            .createQuery(
                                    "update RecoveryChallengeEntity c set c.createdAt = :created, c.expiresAt = :expired where c.challengeId = :challengeId")
                            .setParameter("created", Instant.EPOCH)
                            .setParameter("expired", Instant.EPOCH.plusSeconds(1))
                            .setParameter("challengeId", expiredChallenge)
                            .executeUpdate();
                    return null;
                });
        verify(expiredChallenge, CREDENTIAL, 401);

        String challengeId = JsonPath.read(challenge(username, enrollmentId, 1L), "$.challengeId");
        String token = JsonPath.read(verify(challengeId, CREDENTIAL, 200), "$.token");
        verify(challengeId, CREDENTIAL, 401);
        assertEquals(1L, sessionCount(username));

        transaction(
                () -> {
                    entityManager
                            .createQuery(
                                    "update RecoverySessionEntity s set s.createdAt = :created, s.expiresAt = :expired where s.username = :username")
                            .setParameter("created", Instant.EPOCH)
                            .setParameter("expired", Instant.EPOCH.plusSeconds(1))
                            .setParameter("username", username)
                            .executeUpdate();
                    return null;
                });
        mvc.perform(
                        get("/api/v1/auth/recovery/material")
                                .header(HttpHeaders.AUTHORIZATION, "Recovery " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void concurrentValidCredentialVerificationHasOneWinner() throws Exception {
        String username = "offline-race-alice";
        registerUser(username);
        String enrollmentId = createActiveEnrollment(username);
        String challengeId = JsonPath.read(challenge(username, enrollmentId, 1L), "$.challengeId");
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            List<Future<Integer>> futures = new ArrayList<>();
            for (int worker = 0; worker < 2; worker++) {
                futures.add(
                        executor.submit(
                                () -> {
                                    ready.countDown();
                                    start.await();
                                    return mvc.perform(
                                                    post("/api/v1/auth/recovery/kit")
                                                            .contentType(MediaType.APPLICATION_JSON)
                                                            .content(
                                                                    """
                                                                    {
                                                                      "challengeId": "%s",
                                                                      "accountCredential": "%s"
                                                                    }
                                                                    """
                                                                            .formatted(
                                                                                    challengeId,
                                                                                    CREDENTIAL)))
                                            .andReturn()
                                            .getResponse()
                                            .getStatus();
                                }));
            }
            ready.await();
            start.countDown();
            List<Integer> statuses = new ArrayList<>();
            for (Future<Integer> future : futures) {
                statuses.add(future.get());
            }
            Collections.sort(statuses);
            assertEquals(List.of(200, 401), statuses);
            assertEquals(1L, sessionCount(username));
        } finally {
            executor.shutdownNow();
        }
    }

    private String challenge(String username, String enrollmentId, long generation)
            throws Exception {
        return mvc.perform(
                        post("/api/v1/auth/recovery/challenges")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "username": "%s",
                                          "enrollmentId": "%s",
                                          "generation": %d
                                        }
                                        """
                                                .formatted(username, enrollmentId, generation)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.userExists").doesNotExist())
                .andReturn()
                .getResponse()
                .getContentAsString();
    }

    private String verify(String challengeId, String credential, int expectedStatus)
            throws Exception {
        return mvc.perform(
                        post("/api/v1/auth/recovery/kit")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "challengeId": "%s",
                                          "accountCredential": "%s"
                                        }
                                        """
                                                .formatted(challengeId, credential)))
                .andExpect(status().is(expectedStatus))
                .andExpect(jsonPath("$.accountCredential").doesNotExist())
                .andReturn()
                .getResponse()
                .getContentAsString();
    }

    private String createActiveEnrollment(String username) throws Exception {
        String created =
                mvc.perform(
                                post("/api/v1/recovery/enrollments")
                                        .with(httpBasic(username, PASSWORD))
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(
                                                """
                                                {
                                                  "generation": 1,
                                                  "accountCredential": "%s",
                                                  "wrappingAlgorithm": "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
                                                  "wrappingPublicKey": "recovery-public-key",
                                                  "encryptedPrivateKey": "opaque-encrypted-recovery-private-key"
                                                }
                                                """
                                                        .formatted(CREDENTIAL)))
                        .andExpect(status().isCreated())
                        .andReturn()
                        .getResponse()
                        .getContentAsString();
        String enrollmentId = JsonPath.read(created, "$.enrollmentId");
        mvc.perform(
                        post("/api/v1/recovery/enrollments/{enrollmentId}/commit", enrollmentId)
                                .with(httpBasic(username, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"generation\":1}"))
                .andExpect(status().isOk());
        return enrollmentId;
    }

    private void registerUser(String username) throws Exception {
        mvc.perform(
                        post("/api/v1/users")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {"username":"%s","password":"%s"}
                                        """
                                                .formatted(username, PASSWORD)))
                .andExpect(status().isCreated());
    }

    private int challengeAttempts(String challengeId) {
        return transaction(
                () ->
                        entityManager
                                .createQuery(
                                        "select c.attempts from RecoveryChallengeEntity c where c.challengeId = :challengeId",
                                        Integer.class)
                                .setParameter("challengeId", challengeId)
                                .getSingleResult());
    }

    private long sessionCount(String username) {
        return transaction(
                () ->
                        entityManager
                                .createQuery(
                                        "select count(s) from RecoverySessionEntity s where s.username = :username",
                                        Long.class)
                                .setParameter("username", username)
                                .getSingleResult());
    }

    private boolean databaseContainsText(String value) {
        return transaction(
                () ->
                        entityManager
                                        .createQuery(
                                                "select count(s) from RecoverySessionEntity s where s.tokenHash = :value",
                                                Long.class)
                                        .setParameter("value", value)
                                        .getSingleResult()
                                != 0L);
    }

    private <T> T transaction(java.util.concurrent.Callable<T> action) {
        return new TransactionTemplate(transactionManager)
                .execute(
                        ignored -> {
                            try {
                                return action.call();
                            } catch (Exception e) {
                                throw new IllegalStateException(e);
                            }
                        });
    }
}
