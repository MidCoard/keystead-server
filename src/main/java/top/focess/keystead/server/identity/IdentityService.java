package top.focess.keystead.server.identity;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
class IdentityService {

    private final UserRepository users;
    private final DeviceRepository devices;
    private final PasswordEncoder passwordEncoder;
    private final Clock clock;

    IdentityService(
            @NonNull UserRepository users,
            @NonNull DeviceRepository devices,
            @NonNull PasswordEncoder passwordEncoder,
            @NonNull Clock clock) {
        this.users = users;
        this.devices = devices;
        this.passwordEncoder = passwordEncoder;
        this.clock = clock;
    }

    @Transactional
    void register(@NonNull UserRegistrationRequest request) {
        if (users.exists(request.username())) {
            throw new UserAlreadyExistsException("User already exists");
        }
        Instant now = clock.instant();
        users.insert(
                new StoredUser(
                        request.username(), passwordEncoder.encode(request.password()), now, now));
    }

    @Transactional
    void registerDevice(@NonNull String ownerId, @NonNull DeviceRegistrationRequest request) {
        devices.upsert(
                new StoredDevice(
                        ownerId,
                        request.deviceId(),
                        request.keyAlgorithm(),
                        request.publicKey(),
                        clock.instant()));
    }

    @Transactional(readOnly = true)
    @NonNull List<DeviceResponse> listDevices(@NonNull String ownerId) {
        return devices.list(ownerId).stream().map(DeviceResponse::from).toList();
    }
}
