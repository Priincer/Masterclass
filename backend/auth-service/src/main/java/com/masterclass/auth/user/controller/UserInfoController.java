package com.masterclass.auth.user.controller;

import com.masterclass.auth.security.model.SecurityUser;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserInfoController {

    @GetMapping("/me")
    public ResponseEntity<?> me(Authentication authentication) {
        SecurityUser user = (SecurityUser) authentication.getPrincipal();

        return ResponseEntity.ok(
                new MeResponse(
                        user.getUsername(),
                        user.getId(),
                        user.getDomainRoles()
                )
        );
    }

    private record MeResponse(
            String email,
            Long id,
            Object roles
    ) {}
}