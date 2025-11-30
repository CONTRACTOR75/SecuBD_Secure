# Image officielle Java 21 (plus légère que openjdk:21-jdk)
FROM eclipse-temurin:21-jre-alpine

# Créer un utilisateur non-root (meilleure pratique sécurité)
RUN addgroup --system spring && adduser --system --ingroup spring spring
USER spring:spring

# Répertoire de travail
WORKDIR /app

# Copier le JAR déjà buildé (on va le faire en multi-stage pour gagner du temps)
# Étape 1 : build avec Maven
FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /build

# Copier le wrapper Maven et pom.xml
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .

# Télécharger les dépendances (cache)
RUN ./mvnw dependency:go-offline -B

# Copier le code source et build le JAR
COPY src ./src
RUN ./mvnw clean package -DskipTests -B

# Étape 2 : image finale légère
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=build /build/target/secure-demo-1.0.0.jar app.jar

# Exposer le port dynamique de Render
EXPOSE $PORT

# Lancer l'app
ENTRYPOINT ["java", "-jar", "/app/app.jar"]