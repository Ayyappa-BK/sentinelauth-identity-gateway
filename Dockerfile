FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
COPY src src
RUN --mount=type=cache,target=/root/.m2 mvn -B -Dmaven.wagon.http.retryHandler.count=5 package -DskipTests || mvn -B -U package -DskipTests
FROM eclipse-temurin:21-jre-jammy
RUN groupadd -g 10001 sentinel && useradd -u 10001 -g sentinel -M sentinel
WORKDIR /app
COPY --from=build /build/target/identity-gateway-1.0.0.jar app.jar
USER 10001:10001
EXPOSE 8080 9090
ENTRYPOINT ["java","-jar","/app/app.jar"]
