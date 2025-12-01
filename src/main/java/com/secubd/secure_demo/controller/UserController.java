package com.secubd.secure_demo.controller;

import com.secubd.secure_demo.model.CustomUserDetails;
import com.secubd.secure_demo.model.User;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @GetMapping("/me")
    public User getMe(@AuthenticationPrincipal CustomUserDetails userDetails) {
        return userDetails.getUser();
    }

}