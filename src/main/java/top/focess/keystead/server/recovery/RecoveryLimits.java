package top.focess.keystead.server.recovery;

final class RecoveryLimits {

    static final int CREDENTIAL_MAX_LENGTH = 512;
    static final int PUBLIC_KEY_MAX_LENGTH = 16_384;
    static final int CIPHERTEXT_MAX_LENGTH = 16_384;

    private RecoveryLimits() {}
}
