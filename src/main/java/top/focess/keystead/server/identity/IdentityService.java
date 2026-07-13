package top.focess.keystead.server.identity;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.jspecify.annotations.NonNull;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.server.audit.AuditService;
import top.focess.keystead.server.crypto.ServerCryptoAlgorithmRegistry;
import top.focess.keystead.server.crypto.UnsupportedCryptoAlgorithmException;
import top.focess.keystead.server.vault.VaultDeviceRevocationService;

@Service
class IdentityService {

    private static final Duration CHALLENGE_TTL = Duration.ofMinutes(5);
    private static final int NONCE_BYTES = 32;

    private final UserRepository users;
    private final DeviceRepository devices;
    private final DeviceChallengeRepository challenges;
    private final AuditService audit;
    private final PasswordEncoder passwordEncoder;
    private final Clock clock;
    private final SecureRandom secureRandom;
    private final Validator validator;
    private final DeviceSignatureVerifier signatures;
    private final VaultDeviceRevocationService vaultRevocations;

    IdentityService(
            @NonNull UserRepository users,
            @NonNull DeviceRepository devices,
            @NonNull DeviceChallengeRepository challenges,
            @NonNull AuditService audit,
            @NonNull PasswordEncoder passwordEncoder,
            @NonNull Clock clock,
            @NonNull Validator validator,
            @NonNull DeviceSignatureVerifier signatures,
            @NonNull VaultDeviceRevocationService vaultRevocations) {
        this.users = users;
        this.devices = devices;
        this.challenges = challenges;
        this.audit = audit;
        this.passwordEncoder = passwordEncoder;
        this.clock = clock;
        this.secureRandom = new SecureRandom();
        this.validator = validator;
        this.signatures = signatures;
        this.vaultRevocations = vaultRevocations;
    }

    @Transactional
    void register(@NonNull UserRegistrationRequest request) {
        if (users.exists(request.username())) {
            throw new UserAlreadyExistsException("User already exists");
        }
        validate(request);
        Instant now = clock.instant();
        users.insert(
                new StoredUser(
                        request.username(),
                        passwordEncoder.encode(request.password()),
                        now,
                        now,
                        0L));
    }

    @Transactional
    void registerDevice(@NonNull String ownerId, @NonNull DeviceRegistrationRequest request) {
        devices.find(ownerId, request.deviceId())
                .ifPresent(
                        device -> {
                            throw new DeviceAlreadyExistsException("Device already exists");
                        });
        validate(request);
        request.validateShape();
        if (!ServerCryptoAlgorithmRegistry.isApprovedDeviceProofAlgorithm(request.keyAlgorithm())) {
            throw new UnsupportedCryptoAlgorithmException("Unsupported device key algorithm");
        }
        devices.insert(
                new StoredDevice(
                        ownerId,
                        request.deviceId(),
                        request.keyAlgorithm(),
                        request.publicKey(),
                        request.wrappingKeyAlgorithm(),
                        request.wrappingPublicKey(),
                        clock.instant(),
                        null,
                        null,
                        null));
    }

    @Transactional(readOnly = true)
    @NonNull List<DeviceResponse> listDevices(@NonNull String ownerId) {
        return devices.list(ownerId).stream().map(DeviceResponse::from).toList();
    }

    @Transactional
    @NonNull DeviceChallengeResponse createDeviceChallenge(
            @NonNull String ownerId, @NonNull String deviceId) {
        StoredDevice device =
                devices.find(ownerId, deviceId)
                        .orElseThrow(() -> new DeviceNotFoundException("Device does not exist"));
        if (device.revokedAt() != null) {
            throw new DeviceNotFoundException("Device does not exist");
        }
        Instant now = clock.instant();
        StoredDeviceChallenge challenge =
                new StoredDeviceChallenge(
                        ownerId,
                        deviceId,
                        UUID.randomUUID().toString(),
                        nonce(),
                        now.plus(CHALLENGE_TTL),
                        null,
                        now);
        challenges.insert(challenge);
        return new DeviceChallengeResponse(
                deviceId, challenge.challengeId(), challenge.nonce(), challenge.expiresAt());
    }

    @Transactional
    void proveDevice(
            @NonNull String ownerId,
            @NonNull String deviceId,
            @NonNull DeviceProofRequest request) {
        Instant now = clock.instant();
        StoredDevice device =
                devices.find(ownerId, deviceId)
                        .orElseThrow(() -> new DeviceNotFoundException("Device does not exist"));
        validate(request);
        StoredDeviceChallenge challenge =
                challenges
                        .find(ownerId, deviceId, request.challengeId())
                        .orElseThrow(() -> new DeviceProofFailedException("Device proof failed"));
        byte[] payload = proofPayload(challenge).getBytes(StandardCharsets.UTF_8);
        if (!signatures.verifyRegisteredDevice(device, payload, request.signature())) {
            throw new DeviceProofFailedException("Device proof failed");
        }
        if (challenges.consumeActive(ownerId, deviceId, challenge.challengeId(), now) != 1
                || devices.markVerifiedActive(ownerId, deviceId, now) != 1) {
            throw new DeviceProofFailedException("Device proof failed");
        }
    }

    @Transactional
    void revokeDevice(@NonNull String ownerId, @NonNull String deviceId) {
        devices.find(ownerId, deviceId)
                .orElseThrow(() -> new DeviceNotFoundException("Device does not exist"));
        Instant now = clock.instant();
        if (devices.revokeActive(ownerId, deviceId, now) == 1) {
            vaultRevocations.revokePackages(ownerId, deviceId, now);
            audit.deviceRevoked(ownerId, ownerId, deviceId);
        }
    }

    private void validate(@NonNull DeviceProofRequest request) {
        Set<ConstraintViolation<DeviceProofRequest>> violations = validator.validate(request);
        if (!violations.isEmpty()) {
            throw new InvalidDeviceProofRequestException(
                    violations.iterator().next().getPropertyPath() + " is invalid");
        }
    }

    private void validate(@NonNull DeviceRegistrationRequest request) {
        Set<ConstraintViolation<DeviceRegistrationRequest>> violations =
                validator.validate(request);
        if (!violations.isEmpty()) {
            throw new InvalidDeviceRegistrationRequestException(
                    violations.iterator().next().getPropertyPath() + " is invalid");
        }
    }

    private void validate(@NonNull UserRegistrationRequest request) {
        Set<ConstraintViolation<UserRegistrationRequest>> violations = validator.validate(request);
        if (!violations.isEmpty()) {
            throw new InvalidUserRegistrationRequestException(
                    violations.iterator().next().getPropertyPath() + " is invalid");
        }
    }

    private @NonNull String proofPayload(@NonNull StoredDeviceChallenge challenge) {
        return "keystead-device-proof:v1:" + challenge.challengeId() + ":" + challenge.nonce();
    }

    private @NonNull String nonce() {
        byte[] value = new byte[NONCE_BYTES];
        secureRandom.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }
}
