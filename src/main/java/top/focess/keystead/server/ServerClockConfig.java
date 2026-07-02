package top.focess.keystead.server;

import java.time.Clock;
import org.jspecify.annotations.NonNull;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ServerClockConfig {

    @Bean
    public @NonNull Clock clock() {
        return Clock.systemUTC();
    }
}
