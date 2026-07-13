package top.focess.keystead.server.identity;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import top.focess.keystead.crypto.DefaultCryptoService;

class DeviceRegistrationRequestTest {

    private static final String SAME_P256_X509_PROOF_KEY =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOn42gxY1eS5HupIBrTKdgrrcsbfKfjMh/"
                    + "c5bjli/l7i/pYA3qnOV4d6uJ6ArmWhvJFmP/zDdkw2eD4CbjG6JcQ==";
    private static final String SAME_P256_TINK_WRAPPING_KEY =
            "eyJwcmltYXJ5S2V5SWQiOjc1MjI3MzcyNiwia2V5IjpbeyJrZXlEYXRhIjp7InR5cGVVcmwiOiJ0"
                    + "eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5FY2llc0FlYWRIa2RmUHVibGlj"
                    + "S2V5IiwidmFsdWUiOiJFa1FLQkFnQ0VBTVNPaEk0Q2pCMGVYQmxMbWR2YjJkc1pXRndhWE11WTI5"
                    + "dEwyZHZiMmRzWlM1amNubHdkRzh1ZEdsdWF5NUJaWE5IWTIxTFpYa1NBaEFRR0FFWUFSb2hBRHAr"
                    + "Tm9NV05Ya3VSN3FTQWEweW5ZSzYzTEczeW40eklmM09XNDVZdjVlNElpRUF2NldBTjZwemxlSGVy"
                    + "aWVnSzVsb2J5UlpqLzh3M1pNTm5nK0FtNHh1aVhFPSIsImtleU1hdGVyaWFsVHlwZSI6IkFTWU1N"
                    + "RVRSSUNfUFVCTElDIn0sInN0YXR1cyI6IkVOQUJMRUQiLCJrZXlJZCI6NzUyMjczNzI2LCJvdXRw"
                    + "dXRQcmVmaXhUeXBlIjoiVElOSyJ9XX0NCg==";

    @Test
    void acceptsLegacyProofOnlyRegistration() {
        assertDoesNotThrow(
                () ->
                        new DeviceRegistrationRequest("device-a", "ED25519", "proof-public-key")
                                .validateShape());
    }

    @Test
    void acceptsApprovedWrappingPublicKeyAlgorithms() {
        assertDoesNotThrow(
                () ->
                        request(
                                        DefaultCryptoService.DEVICE_KEY_ALGORITHM,
                                        "tink-wrapping-public-key")
                                .validateShape());
        assertDoesNotThrow(
                () -> request("RSA_OAEP_SHA256", "rsa-wrapping-public-key").validateShape());
    }

    @Test
    void rejectsHalfPresentWrappingPublicKeyPair() {
        assertThrows(
                InvalidDeviceRegistrationRequestException.class,
                () -> request("RSA_OAEP_SHA256", null).validateShape());
        assertThrows(
                InvalidDeviceRegistrationRequestException.class,
                () -> request(null, "rsa-wrapping-public-key").validateShape());
    }

    @Test
    void rejectsWrappedPackageFormatAsWrappingPublicKeyAlgorithm() {
        assertThrows(
                InvalidDeviceRegistrationRequestException.class,
                () ->
                        request("TINK_DEVICE_KEY_PACKAGE", "not-a-public-key-algorithm")
                                .validateShape());
    }

    @Test
    void rejectsReusingProofPublicKeyAsWrappingPublicKey() {
        assertThrows(
                InvalidDeviceRegistrationRequestException.class,
                () ->
                        new DeviceRegistrationRequest(
                                        "device-a",
                                        "RSA_OAEP_SHA256",
                                        "same-public-key",
                                        "RSA_OAEP_SHA256",
                                        "same-public-key")
                                .validateShape());
        assertThrows(
                InvalidDeviceRegistrationRequestException.class,
                () ->
                        new DeviceRegistrationRequest(
                                        "device-a", "ED25519", "AQI=", "RSA_OAEP_SHA256", "AQI")
                                .validateShape());
    }

    @Test
    void rejectsSameP256PublicPointAcrossX509AndTinkEncodings() {
        assertThrows(
                InvalidDeviceRegistrationRequestException.class,
                () ->
                        new DeviceRegistrationRequest(
                                        "device-p256-reuse",
                                        "ECDSA_P256_SHA256",
                                        SAME_P256_X509_PROOF_KEY,
                                        "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
                                        SAME_P256_TINK_WRAPPING_KEY)
                                .validateShape());
    }

    private static DeviceRegistrationRequest request(
            String wrappingKeyAlgorithm, String wrappingPublicKey) {
        return new DeviceRegistrationRequest(
                "device-a", "ED25519", "proof-public-key", wrappingKeyAlgorithm, wrappingPublicKey);
    }
}
