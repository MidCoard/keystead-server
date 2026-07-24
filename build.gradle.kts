plugins {
    java
    id("org.springframework.boot") version "3.5.9"
    id("io.spring.dependency-management") version "1.1.7"
    id("com.diffplug.spotless") version "8.1.0"
}

group = "top.focess"
version = "0.3.0-SNAPSHOT"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
        vendor = JvmVendorSpec.ADOPTIUM
    }
    withSourcesJar()
}

// The server ships as a runnable Spring Boot fat JAR (bootJar); the plain
// classes JAR is not useful (the server is not consumed as a library) and is
// disabled so build/libs/ contains only the runnable artifact. This keeps the
// release Dockerfile's JAR glob unambiguous.
tasks.jar { enabled = false }

dependencies {
    implementation("top.focess:keystead-core:0.2.0")
    implementation("org.jspecify:jspecify:1.0.0")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.flywaydb:flyway-core")
    runtimeOnly("com.h2database:h2")
    runtimeOnly("org.postgresql:postgresql")
    runtimeOnly("org.flywaydb:flyway-database-postgresql")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    // keystead-core runs on the classpath here; its fail-closed native locked memory
    // requires native access to be granted to the unnamed module.
    jvmArgs("--enable-native-access=ALL-UNNAMED")
    // Surface the full cause chain (e.g. Flyway -> PSQLException messages) so a
    // migration failure on a given database lane is self-diagnosing in CI logs
    // instead of showing only "class at File:line".
    testLogging {
        events(org.gradle.api.tasks.testing.logging.TestLogEvent.FAILED)
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        showCauses = true
        showStackTraces = true
    }
}

spotless {
    java {
        googleJavaFormat("1.32.0").aosp()
    }
}
