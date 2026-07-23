FROM eclipse-temurin:25-jre
WORKDIR /app
COPY build/libs/keystead-server-*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
