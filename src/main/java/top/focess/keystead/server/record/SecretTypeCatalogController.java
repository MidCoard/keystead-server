package top.focess.keystead.server.record;

import org.jspecify.annotations.NonNull;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/secret-types")
class SecretTypeCatalogController {

    @GetMapping("/catalog")
    @NonNull SecretTypeCatalogResponse catalog() {
        return SecretTypeCatalogResponse.fromRecordTypes();
    }
}
