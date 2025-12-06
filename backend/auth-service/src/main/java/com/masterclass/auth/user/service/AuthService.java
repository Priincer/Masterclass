package com.masterclass.auth.user.service;

import com.masterclass.auth.common.api.ErrorCode;
import com.masterclass.auth.common.exception.ApiException;
import com.masterclass.auth.security.jwt.JwtTokenService;
import com.masterclass.auth.security.model.SecurityUser;
import com.masterclass.auth.user.domain.PasswordResetToken;
import com.masterclass.auth.user.domain.RefreshToken;
import com.masterclass.auth.user.domain.User;
import com.masterclass.auth.user.dto.AuthResponse;
import com.masterclass.auth.user.dto.LoginRequest;
import com.masterclass.auth.user.dto.RegisterRequest;
import com.masterclass.auth.user.event.UserEventPublisher;
import com.masterclass.auth.user.event.UserRegisteredEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final JwtTokenService jwtTokenService;
    private final RefreshTokenService refreshTokenService;
    private final PasswordResetService passwordResetService;
    private final UserEventPublisher userEventPublisher;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        User user = userService.registerUser(request);
        SecurityUser securityUser = new SecurityUser(user);
        String token = jwtTokenService.generateToken(securityUser);

        RefreshToken refreshToken = refreshTokenService.createToken(user);

        UserRegisteredEvent event = UserRegisteredEvent.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .roles(
                        user.getRoles().stream()
                                .map(Enum::name)
                                .collect(Collectors.toSet())
                )
                .occurredAt(Instant.now())
                .build();

        userEventPublisher.publishUserRegistered(event);

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

        SecurityUser securityUser = (SecurityUser) authentication.getPrincipal();

        User user = userService.findByEmail(securityUser.getUsername())
                .orElseThrow(() -> new ApiException(
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        ErrorCode.INTERNAL_ERROR,
                        "Authenticated user not found"
                ));

        String token = jwtTokenService.generateToken(securityUser);
        RefreshToken refreshToken = refreshTokenService.createToken(user);

        return AuthResponse.builder()
                .accessToken(token)
                .refreshToken(refreshToken.getToken())
                .tokenType("Bearer")
                .build();
    }

    @Transactional
    public void logoutCurrentUser(SecurityUser currentUser) {
        User domainUser = currentUser.getUser();
        refreshTokenService.revokeAllForUser(domainUser);
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

    @Transactional
    public void requestPasswordReset(String email) {
        userService.findByEmail(email).ifPresent(user -> {
            PasswordResetToken token = passwordResetService.createToken(user);

            // TODO: Token per Notification-Service versenden (z.B. E-Mail mit Link)
            // z.B. /reset-password?token=<token.getToken()>
        });

        // Wenn User nicht gefunden -> absichtlich nichts tun.
        // Nach außen immer gleiche Response (Controller: 204 No Content).
    }

    @Transactional
    public void resetPassword(String tokenValue, String newPassword) {

        PasswordResetToken validToken = passwordResetService.findValidToken(tokenValue)
                .orElseThrow(() -> new ApiException(
                        HttpStatus.BAD_REQUEST,
                        ErrorCode.INVALID_PASSWORD_RESET_TOKEN,
                        "Invalid or expired password reset token."
                ));

        User user = validToken.getUser();

        userService.updatePassword(user, newPassword);

        passwordResetService.markAsUsed(validToken);

        refreshTokenService.revokeAllForUser(user);
    }
}