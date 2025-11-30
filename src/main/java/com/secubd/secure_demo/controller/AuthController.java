package com.secubd.secure_demo.controller;

import com.secubd.secure_demo.dto.LoginRequest;
import com.secubd.secure_demo.dto.LoginResponse;
import com.secubd.secure_demo.dto.RegisterRequest;
import com.secubd.secure_demo.model.User;
import com.secubd.secure_demo.model.AuditLog;
import com.secubd.secure_demo.repository.UserRepository;
import com.secubd.secure_demo.repository.AuditLogRepository;
import com.secubd.secure_demo.security.JwtTokenProvider;
import com.secubd.secure_demo.service.SimplePasswordEncoder;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api/auth")
@Validated
@CrossOrigin(
        origins = {"http://localhost:8080", "http://localhost:8081"},
        allowedHeaders = {"Content-Type", "Authorization", "X-CSRF-Token"},
        methods = {RequestMethod.POST, RequestMethod.OPTIONS},
        maxAge = 3600
)
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    // Rate Limiting par IP
    private final Map<String, Bucket> ipBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> userBuckets = new ConcurrentHashMap<>();

    // Configuration de sécurité
    private static final int MAX_FAILED_ATTEMPTS = 3;
    private static final int LOCKOUT_DURATION_MINUTES = 15;
    private static final int PASSWORD_MIN_LENGTH = 12;
    private static final int USERNAME_MIN_LENGTH = 3;
    private static final int USERNAME_MAX_LENGTH = 50;

    // Patterns de validation
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{3,50}$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
    );
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{12,}$"
    );

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    // Rate Limiting: 5 tentatives par minute par IP
    private Bucket createIpBucket() {
        Bandwidth limit = Bandwidth.classic(5, Refill.intervally(5, Duration.ofMinutes(1)));
        return Bucket.builder().addLimit(limit).build();
    }

    // Rate Limiting: 3 tentatives par 5 minutes par utilisateur
    private Bucket createUserBucket() {
        Bandwidth limit = Bandwidth.classic(3, Refill.intervally(3, Duration.ofMinutes(5)));
        return Bucket.builder().addLimit(limit).build();
    }

    private Bucket resolveBucket(String key, Map<String, Bucket> bucketMap, boolean isIp) {
        return bucketMap.computeIfAbsent(key, k -> isIp ? createIpBucket() : createUserBucket());
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private void logAuditEvent(String username, String action, String ipAddress,
                               boolean success, String details) {
        try {
            AuditLog log = new AuditLog();
            log.setUsername(username);
            log.setAction(action);
            log.setIpAddress(ipAddress);
            log.setSuccess(success);
            log.setDetails(details);
            log.setTimestamp(LocalDateTime.now());
            auditLogRepository.save(log);
        } catch (Exception e) {
            logger.error("Erreur lors de l'enregistrement de l'audit", e);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            @Valid @RequestBody LoginRequest loginRequest,
            HttpServletRequest request) {

        String ipAddress = getClientIp(request);
        Map<String, Object> response = new HashMap<>();

        // Rate Limiting par IP
        Bucket ipBucket = resolveBucket(ipAddress, ipBuckets, true);
        if (!ipBucket.tryConsume(1)) {
            logAuditEvent(loginRequest.getUsername(), "LOGIN_RATE_LIMIT", ipAddress, false,
                    "Trop de tentatives depuis cette IP");
            response.put("success", false);
            response.put("message", "Trop de tentatives. Veuillez réessayer dans quelques instants.");
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
        }

        // Validation du format d'entrée
        if (!isValidUsername(loginRequest.getUsername())) {
            logAuditEvent(loginRequest.getUsername(), "LOGIN_INVALID_FORMAT", ipAddress, false,
                    "Format de nom d'utilisateur invalide");
            response.put("success", false);
            response.put("message", "Format de nom d'utilisateur invalide");
            return ResponseEntity.badRequest().body(response);
        }

        String username = sanitizeInput(loginRequest.getUsername());

        // Rate Limiting par utilisateur
        Bucket userBucket = resolveBucket(username, userBuckets, false);
        if (!userBucket.tryConsume(1)) {
            logAuditEvent(username, "LOGIN_USER_RATE_LIMIT", ipAddress, false,
                    "Trop de tentatives pour cet utilisateur");
            response.put("success", false);
            response.put("message", "Trop de tentatives pour ce compte. Veuillez réessayer plus tard.");
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
        }

        Optional<User> optionalUser = userRepository.findByUsername(username);

        if (optionalUser.isEmpty()) {
            // Timing attack prevention: même délai que si l'utilisateur existait
            passwordEncoder.encode("dummy_password_to_prevent_timing_attack");
            logAuditEvent(username, "LOGIN_USER_NOT_FOUND", ipAddress, false,
                    "Utilisateur inexistant");
            response.put("success", false);
            response.put("message", "Identifiants incorrects");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }

        User user = optionalUser.get();

        // Vérifier si le compte est verrouillé
        if (user.getLockedUntil() != null &&
                LocalDateTime.parse(user.getLockedUntil()).isAfter(LocalDateTime.now())) {
            logAuditEvent(username, "LOGIN_ACCOUNT_LOCKED", ipAddress, false,
                    "Tentative de connexion sur compte verrouillé");
            response.put("success", false);
            response.put("message", "Compte temporairement verrouillé. Réessayez après " +
                    user.getLockedUntil());
            response.put("lockedUntil", user.getLockedUntil());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
        }

        // Vérification du mot de passe avec BCrypt
        if (passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            // Réinitialiser les tentatives échouées
            user.setFailedAttempts(0);
            user.setLockedUntil(null);
            user.setLastLoginDate(LocalDateTime.now().toString());
            user.setLastLoginIp(ipAddress);
            userRepository.save(user);

            // Générer un token JWT
            String token = jwtTokenProvider.generateToken(username);
            String refreshToken = jwtTokenProvider.generateRefreshToken(username);

            logAuditEvent(username, "LOGIN_SUCCESS", ipAddress, true, "Connexion réussie");

            response.put("success", true);
            response.put("message", "Connexion réussie");
            response.put("username", username);
            response.put("token", token);
            response.put("refreshToken", refreshToken);
            response.put("expiresIn", jwtTokenProvider.getExpirationTime());

            return ResponseEntity.ok(response);
        } else {
            // Incrémenter les tentatives échouées
            user.setFailedAttempts(user.getFailedAttempts() + 1);

            if (user.getFailedAttempts() >= MAX_FAILED_ATTEMPTS) {
                user.setLockedUntil(LocalDateTime.now()
                        .plus(LOCKOUT_DURATION_MINUTES, ChronoUnit.MINUTES).toString());
                logAuditEvent(username, "LOGIN_ACCOUNT_LOCKED_BY_ATTEMPTS", ipAddress, false,
                        "Compte verrouillé après " + MAX_FAILED_ATTEMPTS + " tentatives");
                response.put("message", "Compte verrouillé pour " + LOCKOUT_DURATION_MINUTES +
                        " minutes après trop de tentatives échouées");
            } else {
                int remainingAttempts = MAX_FAILED_ATTEMPTS - user.getFailedAttempts();
                logAuditEvent(username, "LOGIN_FAILED_PASSWORD", ipAddress, false,
                        "Mot de passe incorrect, " + remainingAttempts + " tentatives restantes");
                response.put("message", "Identifiants incorrects. " + remainingAttempts +
                        " tentative(s) restante(s)");
            }

            userRepository.save(user);
            response.put("success", false);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(
            @Valid @RequestBody RegisterRequest registerRequest,
            HttpServletRequest request) {

        String ipAddress = getClientIp(request);
        Map<String, Object> response = new HashMap<>();

        // Rate Limiting par IP pour les inscriptions
        Bucket ipBucket = resolveBucket(ipAddress, ipBuckets, true);
        if (!ipBucket.tryConsume(1)) {
            logAuditEvent(registerRequest.getUsername(), "REGISTER_RATE_LIMIT", ipAddress,
                    false, "Trop de tentatives d'inscription");
            response.put("success", false);
            response.put("message", "Trop de tentatives. Veuillez réessayer plus tard.");
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
        }

        // Validation complète des entrées
        Map<String, String> validationErrors = validateRegistrationData(registerRequest);
        if (!validationErrors.isEmpty()) {
            logAuditEvent(registerRequest.getUsername(), "REGISTER_VALIDATION_FAILED",
                    ipAddress, false, "Erreurs de validation: " + validationErrors);
            response.put("success", false);
            response.put("message", "Erreurs de validation");
            response.put("errors", validationErrors);
            return ResponseEntity.badRequest().body(response);
        }

        String username = sanitizeInput(registerRequest.getUsername());
        String email = sanitizeInput(registerRequest.getEmail());

        // Vérifier l'existence de l'utilisateur
        if (userRepository.findByUsername(username).isPresent()) {
            logAuditEvent(username, "REGISTER_USERNAME_EXISTS", ipAddress, false,
                    "Nom d'utilisateur déjà pris");
            response.put("success", false);
            response.put("message", "Ce nom d'utilisateur est déjà utilisé");
            return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
        }

        // Vérifier l'existence de l'email
        if (userRepository.findByEmail(email).isPresent()) {
            logAuditEvent(username, "REGISTER_EMAIL_EXISTS", ipAddress, false,
                    "Email déjà utilisé");
            response.put("success", false);
            response.put("message", "Cet email est déjà utilisé");
            return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
        }

        try {
            // Créer le nouvel utilisateur
            User user = new User();
            user.setUsername(username);
            user.setEmail(email);
            user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
            user.setFailedAttempts(0);
            user.setCreatedAt(LocalDateTime.now().toString());
            user.setLastLoginIp(ipAddress);
            user.setEnabled(true); // Peut être false si vérification email requise

            userRepository.save(user);

            // Générer les tokens comme pour le login
            String token = jwtTokenProvider.generateToken(username);
            String refreshToken = jwtTokenProvider.generateRefreshToken(username);

            logAuditEvent(username, "REGISTER_SUCCESS", ipAddress, true,
                    "Compte créé avec succès");
            response.put("success", true);
            response.put("message", "Compte créé avec succès");
            response.put("username", username);
            response.put("token", token);  // AJOUTER
            response.put("refreshToken", refreshToken);  // AJOUTER

            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (Exception e) {
            logger.error("Erreur lors de la création du compte", e);
            logAuditEvent(username, "REGISTER_ERROR", ipAddress, false,
                    "Erreur serveur: " + e.getMessage());
            response.put("success", false);
            response.put("message", "Erreur lors de la création du compte");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refreshToken(
            @RequestBody Map<String, String> request) {

        Map<String, Object> response = new HashMap<>();
        String refreshToken = request.get("refreshToken");

        if (refreshToken == null || !jwtTokenProvider.validateToken(refreshToken)) {
            if (jwtTokenProvider.isTokenExpired(refreshToken)) {
                response.put("message", "Token de rafraîchissement expiré. Veuillez vous reconnecter.");
            } else {
                response.put("message", "Token de rafraîchissement invalide ou forgé.");
            }
            response.put("success", false);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }

        String username = jwtTokenProvider.getUsernameFromToken(refreshToken);
        String newToken = jwtTokenProvider.generateToken(username);

        response.put("success", true);
        response.put("token", newToken);
        response.put("expiresIn", jwtTokenProvider.getExpirationTime());

        return ResponseEntity.ok(response);
    }

    // Méthodes utilitaires privées

    private Map<String, String> validateRegistrationData(RegisterRequest request) {
        Map<String, String> errors = new HashMap<>();

        // Validation du nom d'utilisateur
        if (!isValidUsername(request.getUsername())) {
            errors.put("username", "Le nom d'utilisateur doit contenir entre " +
                    USERNAME_MIN_LENGTH + " et " + USERNAME_MAX_LENGTH +
                    " caractères (lettres, chiffres, tirets et underscores uniquement)");
        }

        // Validation de l'email
        if (!isValidEmail(request.getEmail())) {
            errors.put("email", "Format d'email invalide");
        }

        // Validation du mot de passe
        if (!isValidPassword(request.getPassword())) {
            errors.put("password", "Le mot de passe doit contenir au moins " +
                    PASSWORD_MIN_LENGTH + " caractères, incluant majuscules, minuscules, " +
                    "chiffres et caractères spéciaux");
        }

        return errors;
    }

    private boolean isValidUsername(String username) {
        return username != null && USERNAME_PATTERN.matcher(username).matches();
    }

    private boolean isValidEmail(String email) {
        return email != null && EMAIL_PATTERN.matcher(email).matches();
    }

    private boolean isValidPassword(String password) {
        return password != null &&
                password.length() >= PASSWORD_MIN_LENGTH &&
                PASSWORD_PATTERN.matcher(password).matches();
    }

    private String sanitizeInput(String input) {
        if (input == null) return null;
        // Supprimer les caractères potentiellement dangereux
        return input.trim()
                .replaceAll("[<>\"'%;()&+]", "")
                .substring(0, Math.min(input.length(), 255));
    }
}