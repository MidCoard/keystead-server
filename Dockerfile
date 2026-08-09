FROM eclipse-temurin:25-jre
WORKDIR /app
COPY build/libs/keystead-server-*.jar app.jar
EXPOSE 22144
ENTRYPOINT ["java", "-jar", "app.jar"]
