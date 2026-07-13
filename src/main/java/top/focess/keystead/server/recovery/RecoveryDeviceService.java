package top.focess.keystead.server.recovery;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.recovery.RecoveryDeviceRequest;
import top.focess.keystead.recovery.RecoveryDeviceRequestCodec;
import top.focess.keystead.server.crypto.ServerCryptoAlgorithmRegistry;
import top.focess.keystead.server.identity.DeviceSignatureVerifier;
import top.focess.keystead.server.vault.VaultAccessGuard;
import top.focess.keystead.server.vault.VaultKeyRotationService;

@Service
class RecoveryDeviceService {

    private static final Duration REQUEST_TTL = Duration.ofMinutes(10);
    private static final int NONCE_BYTES = 32;

    private final RecoveryRequestRepository requests;
    private final RecoveryRequestVaultPackageRepository requestPackages;
    private final RecoverySessionService sessions;
    private final DeviceSignatureVerifier signatures;
    private final VaultAccessGuard vaultAccess;
    private final VaultKeyRotationService rotations;
    private final Validator validator;
    private final Clock clock;
    private final SecureRandom secureRandom = new SecureRandom();

    RecoveryDeviceService(
            @NonNull RecoveryRequestRepository requests,
            @NonNull RecoveryRequestVaultPackageRepository requestPackages,
            @NonNull RecoverySessionService sessions,
            @NonNull DeviceSignatureVerifier signatures,
            @NonNull VaultAccessGuard vaultAccess,
            @NonNull VaultKeyRotationService rotations,
            @NonNull Validator validator,
            @NonNull Clock clock) {
        this.requests = requests;
        this.requestPackages = requestPackages;
        this.sessions = sessions;
        this.signatures = signatures;
        this.vaultAccess = vaultAccess;
        this.rotations = rotations;
        this.validator = validator;
        this.clock = clock;
    }

    @Transactional
    @NonNull RecoveryDeviceRequestResponse create(@NonNull RecoveryDeviceRequestPayload payload) {
        validate(payload);
        requireAlgorithmsAndKeys(payload);
        Instant now = clock.instant();
        Instant expiresAt = now.plus(REQUEST_TTL).truncatedTo(ChronoUnit.SECONDS);
        RecoveryRequestEntity entity = new RecoveryRequestEntity();
        entity.requestId = UUID.randomUUID().toString();
        entity.username = payload.username();
        entity.nonce = nonce();
        entity.deviceId = payload.deviceId();
        entity.proofKeyAlgorithm = payload.proofKeyAlgorithm();
        entity.proofPublicKey = payload.proofPublicKey();
        entity.wrappingKeyAlgorithm = payload.wrappingKeyAlgorithm();
        entity.wrappingPublicKey = payload.wrappingPublicKey();
        entity.state = RecoveryRequestState.PENDING;
        entity.expiresAt = expiresAt;
        entity.createdAt = now;
        entity.fingerprint = fingerprint(entity);
        return response(requests.saveAndFlush(entity));
    }

    @Transactional(readOnly = true)
    @NonNull List<RecoveryDeviceRequestResponse> listPending(@NonNull String username) {
        return requests.listPending(username, clock.instant()).stream()
                .map(this::response)
                .toList();
    }

    @Transactional(readOnly = true)
    @NonNull RecoveryDeviceRequestResponse status(@NonNull String requestId) {
        return response(
                requests.findById(requestId)
                        .orElseThrow(RecoveryAuthenticationFailedException::new));
    }

    @Transactional
    void approve(
            @NonNull String username,
            @NonNull String requestId,
            @NonNull RecoveryDeviceApprovalRequest approval) {
        validate(approval);
        RecoveryRequestEntity request =
                activeRequest(username, requestId, RecoveryRequestState.PENDING);
        byte[] canonical = canonical(request);
        try {
            if (!signatures.verifyVerifiedDevice(
                    username, approval.deviceId(), canonical, approval.signature())) {
                throw new RecoveryAuthenticationFailedException();
            }
        } finally {
            Arrays.fill(canonical, (byte) 0);
        }
        List<RecoveryRequestVaultPackageEntity> packages =
                validateAndMapPackages(username, requestId, approval.vaultPackages());
        Instant now = clock.instant();
        if (requests.approvePending(requestId, username, approval.deviceId(), now) != 1) {
            throw new RecoveryAuthenticationFailedException();
        }
        requestPackages.saveAll(packages);
        requestPackages.flush();
    }

    @Transactional
    @NonNull RecoverySessionResponse claim(
            @NonNull String requestId, @NonNull RecoveryDeviceClaimRequest claim) {
        validate(claim);
        RecoveryRequestEntity request =
                requests.findById(requestId)
                        .filter(value -> value.state == RecoveryRequestState.APPROVED)
                        .filter(value -> value.expiresAt.isAfter(clock.instant()))
                        .orElseThrow(RecoveryAuthenticationFailedException::new);
        byte[] canonical = canonical(request);
        try {
            if (!signatures.verifyPublicKey(
                    request.proofKeyAlgorithm,
                    request.proofPublicKey,
                    canonical,
                    claim.signature())) {
                throw new RecoveryAuthenticationFailedException();
            }
        } finally {
            Arrays.fill(canonical, (byte) 0);
        }
        Instant now = clock.instant();
        if (requests.consumeApproved(requestId, now) != 1) {
            throw new RecoveryAuthenticationFailedException();
        }
        return sessions.issueDeviceSession(request, now);
    }

    private @NonNull RecoveryRequestEntity activeRequest(
            @NonNull String username,
            @NonNull String requestId,
            @NonNull RecoveryRequestState state) {
        Instant now = clock.instant();
        return requests.findById(requestId)
                .filter(value -> value.username.equals(username))
                .filter(value -> value.state == state)
                .filter(value -> value.expiresAt.isAfter(now))
                .orElseThrow(RecoveryAuthenticationFailedException::new);
    }

    private @NonNull List<RecoveryRequestVaultPackageEntity> validateAndMapPackages(
            @NonNull String username,
            @NonNull String requestId,
            @NonNull List<RecoveryApprovalVaultPackage> values) {
        Set<String> vaultIds = new HashSet<>();
        List<RecoveryRequestVaultPackageEntity> mapped = new ArrayList<>();
        Instant now = clock.instant();
        for (RecoveryApprovalVaultPackage value : values) {
            validate(value);
            if (!vaultIds.add(value.vaultId())) {
                throw new InvalidRecoveryRequestException("Recovery package vault is duplicated");
            }
            if (!ServerCryptoAlgorithmRegistry.DEVICE_TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
                    .equals(value.keyAlgorithm())) {
                throw new InvalidRecoveryRequestException(
                        "Recovery package algorithm is unsupported");
            }
            String ownerId =
                    vaultAccess.requireActiveMemberAndResolveOwner(username, value.vaultId());
            rotations.requireCurrentOrLegacy(ownerId, value.vaultId(), value.vaultKeyId());
            RecoveryRequestVaultPackageEntity entity = new RecoveryRequestVaultPackageEntity();
            entity.id = new RecoveryRequestVaultPackageId(requestId, value.vaultId());
            entity.vaultKeyId = value.vaultKeyId();
            entity.keyAlgorithm = value.keyAlgorithm();
            entity.encryptedVaultKey = value.encryptedVaultKey();
            entity.createdAt = now;
            mapped.add(entity);
        }
        return mapped;
    }

    private void requireAlgorithmsAndKeys(@NonNull RecoveryDeviceRequestPayload payload) {
        if (!ServerCryptoAlgorithmRegistry.isApprovedDeviceProofAlgorithm(
                        payload.proofKeyAlgorithm())
                || !signatures.isValidPublicKey(
                        payload.proofKeyAlgorithm(), payload.proofPublicKey())) {
            throw new InvalidRecoveryRequestException("Recovery proof public key is invalid");
        }
        if (!ServerCryptoAlgorithmRegistry.DEVICE_TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
                .equals(payload.wrappingKeyAlgorithm())) {
            throw new InvalidRecoveryRequestException("Recovery wrapping algorithm is unsupported");
        }
        byte[] wrapping = decodeKey(payload.wrappingPublicKey());
        Arrays.fill(wrapping, (byte) 0);
        if (payload.proofPublicKey().equals(payload.wrappingPublicKey())) {
            throw new InvalidRecoveryRequestException(
                    "Recovery proof and wrapping keys must be distinct");
        }
    }

    private @NonNull RecoveryDeviceRequestResponse response(@NonNull RecoveryRequestEntity entity) {
        byte[] canonical = canonical(entity);
        try {
            RecoveryRequestState state =
                    entity.state == RecoveryRequestState.PENDING
                                    && !entity.expiresAt.isAfter(clock.instant())
                            ? RecoveryRequestState.EXPIRED
                            : entity.state;
            return new RecoveryDeviceRequestResponse(
                    entity.requestId,
                    entity.username,
                    entity.deviceId,
                    entity.fingerprint,
                    state,
                    entity.expiresAt,
                    Base64.getUrlEncoder().withoutPadding().encodeToString(canonical));
        } finally {
            Arrays.fill(canonical, (byte) 0);
        }
    }

    private @NonNull String fingerprint(@NonNull RecoveryRequestEntity entity) {
        return RecoveryDeviceRequestCodec.fingerprint(coreRequest(entity));
    }

    private byte @NonNull [] canonical(@NonNull RecoveryRequestEntity entity) {
        return RecoveryDeviceRequestCodec.encode(coreRequest(entity));
    }

    private @NonNull RecoveryDeviceRequest coreRequest(@NonNull RecoveryRequestEntity entity) {
        byte[] proof = decodeKey(entity.proofPublicKey);
        byte[] wrapping = decodeKey(entity.wrappingPublicKey);
        try {
            return new RecoveryDeviceRequest(
                    RecoveryDeviceRequest.FORMAT_VERSION,
                    entity.requestId,
                    entity.username,
                    entity.nonce,
                    entity.expiresAt,
                    entity.deviceId,
                    entity.proofKeyAlgorithm,
                    proof,
                    entity.wrappingKeyAlgorithm,
                    wrapping);
        } finally {
            Arrays.fill(proof, (byte) 0);
            Arrays.fill(wrapping, (byte) 0);
        }
    }

    private byte @NonNull [] decodeKey(@NonNull String encoded) {
        try {
            byte[] value = Base64.getDecoder().decode(encoded);
            if (value.length == 0 || value.length > 64 * 1024) {
                Arrays.fill(value, (byte) 0);
                throw new InvalidRecoveryRequestException("Recovery public key is invalid");
            }
            return value;
        } catch (IllegalArgumentException e) {
            throw new InvalidRecoveryRequestException("Recovery public key is invalid");
        }
    }

    private @NonNull String nonce() {
        byte[] value = new byte[NONCE_BYTES];
        secureRandom.nextBytes(value);
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
        } finally {
            Arrays.fill(value, (byte) 0);
        }
    }

    private <T> void validate(@NonNull T request) {
        Set<ConstraintViolation<T>> violations = validator.validate(request);
        if (!violations.isEmpty()) {
            throw new InvalidRecoveryRequestException("Recovery request is invalid");
        }
    }
}
