package top.focess.keystead.server.vaultaccess;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.access.VaultAccessRequest;
import top.focess.keystead.access.VaultAccessRequestCodec;
import top.focess.keystead.memory.Wipe;
import top.focess.keystead.server.crypto.ServerCryptoAlgorithmRegistry;

@Service
class VaultAccessRequestService {

    private static final Duration REQUEST_TTL = Duration.ofMinutes(10);
    private static final int MAX_DECODED_KEY_BYTES = 64 * 1024;

    private final VaultAccessRequestRepository requests;
    private final Validator validator;
    private final Clock clock;

    VaultAccessRequestService(
            @NonNull VaultAccessRequestRepository requests,
            @NonNull Validator validator,
            @NonNull Clock clock) {
        this.requests = requests;
        this.validator = validator;
        this.clock = clock;
    }

    @Transactional
    @NonNull VaultAccessRequestResponse create(
            @NonNull String username, @NonNull VaultAccessCreateRequest payload) {
        validate(payload);
        if (!ServerCryptoAlgorithmRegistry.isApprovedVaultAccessExchangeKeyAlgorithm(
                payload.keyAlgorithm())) {
            throw new InvalidVaultAccessRequestException(
                    "Ephemeral exchange key algorithm is unsupported");
        }
        Instant now = clock.instant();
        VaultAccessRequestEntity entity = new VaultAccessRequestEntity();
        entity.requestId = payload.requestId();
        entity.username = username;
        entity.serverOrigin = payload.serverOrigin();
        entity.keyAlgorithm = payload.keyAlgorithm();
        entity.exchangePublicKey = payload.exchangePublicKey();
        entity.state = VaultAccessRequestState.PENDING;
        entity.expiresAt = now.plus(REQUEST_TTL).truncatedTo(ChronoUnit.SECONDS);
        entity.createdAt = now;
        entity.fingerprint = fingerprint(entity);
        try {
            return response(requests.saveAndFlush(entity));
        } catch (DataIntegrityViolationException error) {
            throw new InvalidVaultAccessRequestException("Vault access request id is already used");
        }
    }

    @Transactional(readOnly = true)
    @NonNull List<VaultAccessRequestResponse> listPending(@NonNull String username) {
        return requests.listPending(username, clock.instant()).stream()
                .map(this::response)
                .toList();
    }

    @Transactional(readOnly = true)
    @NonNull VaultAccessRequestResponse status(
            @NonNull String username, @NonNull String requestId) {
        return response(request(username, requestId));
    }

    @Transactional
    void approve(
            @NonNull String username,
            @NonNull String requestId,
            @NonNull VaultAccessApprovalRequest approval) {
        validate(approval);
        if (!ServerCryptoAlgorithmRegistry.isApprovedVaultAccessWrappedKeyAlgorithm(
                approval.keyAlgorithm())) {
            throw new InvalidVaultAccessRequestException(
                    "Wrapped vault key algorithm is unsupported");
        }
        request(username, requestId);
        Instant now = clock.instant();
        if (requests.approvePending(
                        requestId,
                        username,
                        approval.vaultFingerprint(),
                        approval.vaultKeyId(),
                        approval.keyAlgorithm(),
                        approval.encryptedVaultKey(),
                        now)
                != 1) {
            throw new VaultAccessDeniedException();
        }
    }

    private @NonNull VaultAccessRequestEntity request(
            @NonNull String username, @NonNull String requestId) {
        return requests.findById(requestId)
                .filter(value -> value.username.equals(username))
                .orElseThrow(VaultAccessRequestNotFoundException::new);
    }

    private @NonNull VaultAccessRequestResponse response(@NonNull VaultAccessRequestEntity entity) {
        byte[] canonical = canonical(entity);
        try {
            VaultAccessRequestState state =
                    entity.state == VaultAccessRequestState.PENDING
                                    && !entity.expiresAt.isAfter(clock.instant())
                            ? VaultAccessRequestState.EXPIRED
                            : entity.state;
            VaultAccessApprovedPackageResponse approved =
                    entity.encryptedVaultKey == null
                            ? null
                            : new VaultAccessApprovedPackageResponse(
                                    entity.vaultFingerprint,
                                    entity.vaultKeyId,
                                    entity.packageKeyAlgorithm,
                                    entity.encryptedVaultKey);
            return new VaultAccessRequestResponse(
                    entity.requestId,
                    entity.username,
                    entity.serverOrigin,
                    entity.fingerprint,
                    entity.keyAlgorithm,
                    entity.exchangePublicKey,
                    state,
                    entity.expiresAt,
                    Base64.getUrlEncoder().withoutPadding().encodeToString(canonical),
                    approved,
                    entity.approvedAt);
        } finally {
            Wipe.wipe(canonical);
        }
    }

    private @NonNull String fingerprint(@NonNull VaultAccessRequestEntity entity) {
        return VaultAccessRequestCodec.fingerprint(coreRequest(entity));
    }

    private byte @NonNull [] canonical(@NonNull VaultAccessRequestEntity entity) {
        return VaultAccessRequestCodec.encode(coreRequest(entity));
    }

    private @NonNull VaultAccessRequest coreRequest(@NonNull VaultAccessRequestEntity entity) {
        byte[] publicKey = decodeKey(entity.exchangePublicKey);
        try {
            return new VaultAccessRequest(
                    VaultAccessRequest.FORMAT_VERSION,
                    entity.requestId,
                    entity.username,
                    entity.serverOrigin,
                    entity.expiresAt,
                    entity.keyAlgorithm,
                    publicKey);
        } finally {
            Wipe.wipe(publicKey);
        }
    }

    private byte @NonNull [] decodeKey(@NonNull String encoded) {
        try {
            byte[] value = Base64.getDecoder().decode(encoded);
            if (value.length == 0 || value.length > MAX_DECODED_KEY_BYTES) {
                Wipe.wipe(value);
                throw new InvalidVaultAccessRequestException(
                        "Ephemeral exchange public key is invalid");
            }
            return value;
        } catch (IllegalArgumentException error) {
            throw new InvalidVaultAccessRequestException(
                    "Ephemeral exchange public key is invalid");
        }
    }

    private <T> void validate(@NonNull T request) {
        Set<ConstraintViolation<T>> violations = validator.validate(request);
        if (!violations.isEmpty()) {
            throw new InvalidVaultAccessRequestException("Vault access request is invalid");
        }
    }
}
