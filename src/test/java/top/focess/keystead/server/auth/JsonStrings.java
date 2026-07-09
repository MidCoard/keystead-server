package top.focess.keystead.server.auth;

import java.nio.charset.StandardCharsets;
import org.jspecify.annotations.NonNull;
import org.springframework.test.web.servlet.MvcResult;

final class JsonStrings {

    private JsonStrings() {}

    static @NonNull String field(@NonNull MvcResult result, @NonNull String field)
            throws Exception {
        String body = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
        String key = "\"" + field + "\":\"";
        int start = body.indexOf(key);
        if (start < 0) {
            throw new IllegalArgumentException("Missing JSON string field: " + field);
        }
        int valueStart = start + key.length();
        int valueEnd = body.indexOf('"', valueStart);
        if (valueEnd < 0) {
            throw new IllegalArgumentException("Unterminated JSON string field: " + field);
        }
        return body.substring(valueStart, valueEnd);
    }
}
