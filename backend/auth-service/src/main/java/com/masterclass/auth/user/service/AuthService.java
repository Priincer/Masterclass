package com.masterclass.auth.user.service;

import com.masterclass.auth.security.model.SecurityUser;
import com.masterclass.auth.security.jwt.JwtTokenService;
import com.masterclass.auth.user.domain.User;
import com.masterclass.auth.user.dto.AuthResponse;
import com.masterclass.auth.user.dto.LoginRequest;
import com.masterclass.auth.user.dto.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final JwtTokenService jwtTokenService;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        User user = userService.registerUser(request);
        SecurityUser securityUser = new SecurityUser(user);
        String token = jwtTokenService.generateToken(securityUser);

        return AuthResponse.builder()
                .accessToken(token)
                .tokenType("Bearer")
                .build();
    }

    @Transactional(readOnly = true)
    public AuthResponse login(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        SecurityUser principal = (SecurityUser) authentication.getPrincipal();
        String token = jwtTokenService.generateToken(principal);

        return AuthResponse.builder()
                .accessToken(token)
                .tokenType("Bearer")
                .build();
    }
}