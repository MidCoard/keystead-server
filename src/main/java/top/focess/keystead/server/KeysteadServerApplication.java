package top.focess.keystead.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class KeysteadServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(KeysteadServerApplication.class, args);
    }
}
