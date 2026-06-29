# Build stage
FROM eclipse-temurin:17-jdk-alpine AS build
WORKDIR /app

COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
COPY api/pom.xml api/pom.xml
COPY persistence/pom.xml persistence/pom.xml
COPY service/pom.xml service/pom.xml
COPY web/pom.xml web/pom.xml

RUN chmod +x mvnw && ./mvnw -q dependency:go-offline -pl web -am

COPY api/src api/src
COPY persistence/src persistence/src
COPY service/src service/src
COPY web/src web/src

RUN ./mvnw -q -pl web -am package -DskipTests

# Runtime stage
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

COPY --from=build /app/web/target/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
