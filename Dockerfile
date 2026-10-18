# syntax=docker/dockerfile:1

# Stage 1: Build
FROM eclipse-temurin:25-jdk AS build
WORKDIR /build

# Copy Maven wrapper and POM to leverage layer caching for dependencies
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
RUN sed -i 's/\r$//' mvnw && chmod +x mvnw
RUN ./mvnw dependency:go-offline -B

# Copy application source and package the jar
COPY src/ src/
RUN ./mvnw clean package -DskipTests -B && \
    cp target/graphguard-*.jar app.jar

# Stage 2: Runtime
FROM eclipse-temurin:25-jre AS runtime
WORKDIR /app

# Install wget for container healthcheck and create non-root user
RUN apt-get update && \
    apt-get install -y --no-install-recommends wget && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -r -u 1001 -g root graphguard

# Copy built application jar from build stage with appropriate permissions
COPY --from=build --chown=graphguard:root /build/app.jar app.jar

USER 1001

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -qO- http://localhost:8080/api/health || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]
