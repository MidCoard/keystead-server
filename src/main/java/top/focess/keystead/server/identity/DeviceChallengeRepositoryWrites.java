package top.focess.keystead.server.identity;

import org.jspecify.annotations.NonNull;

interface DeviceChallengeRepositoryWrites {

    void insert(@NonNull StoredDeviceChallenge challenge);
}
