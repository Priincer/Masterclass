package com.masterclass.auth.user.service;

import com.masterclass.auth.security.jwt.JwtTokenService;
import com.masterclass.auth.security.model.SecurityUser;
import com.masterclass.auth.user.domain.RefreshToken;
import com.masterclass.auth.user.domain.Role;
import com.masterclass.auth.user.domain.User;
import com.masterclass.auth.user.dto.AuthResponse;
import com.masterclass.auth.user.dto.LoginRequest;
import com.masterclass.auth.user.dto.RegisterRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private UserService userService;

    @Mock
    private JwtTokenService jwtTokenService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @InjectMocks
    private AuthService authService;

    private User user;
    private SecurityUser securityUser;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .id(1L)
                .email("test@example.com")
                .password("encoded-password")
                .firstName("Test")
                .lastName("User")
                .roles(Set.of(Role.USER))
                .build();

        securityUser = new SecurityUser(user);
    }

    @Test
    void register_shouldReturnAuthResponseWithTokens() {
        RegisterRequest request = RegisterRequest.builder()
                .email("test@example.com")
                .password("password")
                .firstName("Test")
                .lastName("User")
                .build();

        when(userService.registerUser(request)).thenReturn(user);
        when(jwtTokenService.generateToken(any(SecurityUser.class)))
                .thenReturn("dummy-jwt-token");
        when(refreshTokenService.createToken(user))
                .thenReturn(RefreshToken.builder()
                        .token("dummy-refresh-token")
                        .user(user)
                        .build()
                );

        AuthResponse response = authService.register(request);

        assertThat(response.getAccessToken()).isEqualTo("dummy-jwt-token");
        assertThat(response.getRefreshToken()).isEqualTo("dummy-refresh-token");
        assertThat(response.getTokenType()).isEqualTo("Bearer");

        verify(userService).registerUser(request);
        verify(jwtTokenService).generateToken(any(SecurityUser.class));
        verify(refreshTokenService).createToken(user);
        verifyNoMoreInteractions(authenticationManager, userService, jwtTokenService, refreshTokenService);
    }

    @Test
    void login_shouldReturnAuthResponseWithTokens() {
        LoginRequest request = LoginRequest.builder()
                .email("test@example.com")
                .password("password")
                .build();

        Authentication authentication = mock(Authentication.class);

        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(securityUser);

        when(userService.findByEmail("test@example.com"))
                .thenReturn(Optional.of(user));

        when(jwtTokenService.generateToken(any(SecurityUser.class)))
                .thenReturn("login-jwt-token");
        when(refreshTokenService.createToken(user))
                .thenReturn(RefreshToken.builder()
                        .token("login-refresh-token")
                        .user(user)
                        .build()
                );

        AuthResponse response = authService.login(request);

        assertThat(response.getAccessToken()).isEqualTo("login-jwt-token");
        assertThat(response.getRefreshToken()).isEqualTo("login-refresh-token");
        assertThat(response.getTokenType()).isEqualTo("Bearer");

        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(authentication).getPrincipal();
        verify(userService).findByEmail("test@example.com");
        verify(jwtTokenService).generateToken(any(SecurityUser.class));
        verify(refreshTokenService).createToken(user);
        verifyNoMoreInteractions(authenticationManager, userService, jwtTokenService, refreshTokenService);
    }
}