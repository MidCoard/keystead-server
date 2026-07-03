package top.focess.keystead.server.crypto;

import org.jspecify.annotations.NonNull;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/crypto")
class CryptoAlgorithmController {

    @GetMapping("/algorithms")
    @NonNull CryptoAlgorithmCatalogResponse algorithms() {
        return CryptoAlgorithmCatalogResponse.fromRegistry();
    }
}
