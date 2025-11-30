# Étape 1 : Build avec Maven
FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /build

# Copier le wrapper Maven et pom.xml
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .

# 🔧 CORRECTION : Rendre mvnw exécutable
RUN chmod +x ./mvnw

# Télécharger les dépendances (cache)
RUN ./mvnw dependency:go-offline -B

# Copier le code source et build le JAR
COPY src ./src
RUN ./mvnw clean package -DskipTests -B

# Étape 2 : Image finale légère
FROM eclipse-temurin:21-jre-alpine

# Créer un utilisateur non-root (meilleure pratique sécurité)
RUN addgroup --system spring && adduser --system --ingroup spring spring
USER spring:spring

# Répertoire de travail
WORKDIR /app

# Copier le JAR depuis l'étape de build
COPY --from=build /build/target/secure-demo-1.0.0.jar app.jar

# Exposer le port dynamique de Render
EXPOSE ${PORT:-8081}

# Lancer l'app avec liaison au port dynamique
ENTRYPOINT ["sh", "-c", "java -jar /app/app.jar --server.port=${PORT:-8081}"]