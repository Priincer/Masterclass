package com.masterclass.auth.user.service;

import com.masterclass.auth.common.api.ErrorCode;
import com.masterclass.auth.common.exception.ApiException;
import com.masterclass.auth.security.jwt.JwtTokenService;
import com.masterclass.auth.security.model.SecurityUser;
import com.masterclass.auth.user.domain.RefreshToken;
import com.masterclass.auth.user.domain.User;
import com.masterclass.auth.user.dto.AuthResponse;
import com.masterclass.auth.user.dto.LoginRequest;
import com.masterclass.auth.user.dto.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
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
    private final RefreshTokenService refreshTokenService;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        User user = userService.registerUser(request);
        SecurityUser securityUser = new SecurityUser(user);
        String token = jwtTokenService.generateToken(securityUser);

        RefreshToken refreshToken = refreshTokenService.createToken(user);

        return AuthResponse.builder()
                .accessToken(token)
                .refreshToken(refreshToken.getToken())
                .tokenType("Bearer")
                .build();
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        SecurityUser principal = (SecurityUser) authentication.getPrincipal();
        String token = jwtTokenService.generateToken(principal);

        User user = userService.findByEmail(principal.getUsername())
                .orElseThrow(() -> new ApiException(
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        ErrorCode.INTERNAL_ERROR,
                        "Authenticated user not found"
                ));

        RefreshToken refreshToken = refreshTokenService.createToken(user);

        return AuthResponse.builder()
                .accessToken(token)
                .refreshToken(refreshToken.getToken())
                .tokenType("Bearer")
                .build();
    }

    @Transactional
    public AuthResponse refresh(String refreshTokenValue) {

        RefreshToken validToken = refreshTokenService.findValidToken(refreshTokenValue)
                .orElseThrow(() -> new ApiException(
                        HttpStatus.UNAUTHORIZED,
                        ErrorCode.INVALID_REFRESH_TOKEN,
                        "Invalid or expired refresh token."
                ));

        User user = validToken.getUser();
        SecurityUser securityUser = new SecurityUser(user);

        refreshTokenService.revoke(validToken);

        RefreshToken newRefreshToken = refreshTokenService.createToken(user);

        String newAccessToken = jwtTokenService.generateToken(securityUser);

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken.getToken())
                .tokenType("Bearer")
                .build();
    }
}