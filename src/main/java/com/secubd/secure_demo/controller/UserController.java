package com.secubd.secure_demo.controller;

import com.secubd.secure_demo.model.CustomUserDetails;
import com.secubd.secure_demo.model.User;
import com.secubd.secure_demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    // Endpoint sécurisé pour récupérer un utilisateur
    @GetMapping("/me")
    public User getMe(@AuthenticationPrincipal CustomUserDetails userDetails) {
        return userDetails.getUser();
    }



}