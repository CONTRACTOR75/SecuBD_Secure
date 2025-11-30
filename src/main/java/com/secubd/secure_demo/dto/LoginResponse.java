package com.secubd.secure_demo.dto;

public class LoginResponse {
    private boolean success;
    private String message;
    private String token;
    private String refreshToken;
    private String username;
    private Long expiresIn;

    public LoginResponse(boolean success, String message) {
        this.success = success;
        this.message = message;
    }

    // Getters et Setters
    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }
    public String getRefreshToken() { return refreshToken; }
    public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public Long getExpiresIn() { return expiresIn; }
    public void setExpiresIn(Long expiresIn) { this.expiresIn = expiresIn; }
}