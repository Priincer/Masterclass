package com.masterclass.auth.user.service;

import com.masterclass.auth.common.api.ErrorCode;
import com.masterclass.auth.common.exception.ApiException;
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
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;
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

    // ------------------------------------------------------------------------
    // register
    // ------------------------------------------------------------------------

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

    // ------------------------------------------------------------------------
    // login
    // ------------------------------------------------------------------------

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

    @Test
    void login_shouldThrowApiException_whenAuthenticatedUserNotFound() {
        LoginRequest request = LoginRequest.builder()
                .email("test@example.com")
                .password("password")
                .build();

        Authentication authentication = mock(Authentication.class);

        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(securityUser);
        when(userService.findByEmail("test@example.com"))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(ApiException.class)
                .satisfies(ex -> {
                    ApiException apiEx = (ApiException) ex;
                    assertThat(apiEx.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
                    assertThat(apiEx.getErrorCode()).isEqualTo(ErrorCode.INTERNAL_ERROR);
                });

        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(authentication).getPrincipal();
        verify(userService).findByEmail("test@example.com");
        verifyNoMoreInteractions(authenticationManager, userService, jwtTokenService, refreshTokenService);
    }

    // ------------------------------------------------------------------------
    // logout
    // ------------------------------------------------------------------------

    @Test
    void logoutCurrentUser_shouldRevokeAllTokensForUser() {
        authService.logoutCurrentUser(securityUser);

        verify(refreshTokenService).revokeAllForUser(user);
        verifyNoMoreInteractions(authenticationManager, userService, jwtTokenService, refreshTokenService);
    }

    // ------------------------------------------------------------------------
    // refresh
    // ------------------------------------------------------------------------

    @Test
    void refresh_shouldReturnNewTokens_whenRefreshTokenIsValid() {
        RefreshToken existingToken = RefreshToken.builder()
                .token("old-refresh-token")
                .user(user)
                .revoked(false)
                .build();

        RefreshToken newToken = RefreshToken.builder()
                .token("new-refresh-token")
                .user(user)
                .revoked(false)
                .build();

        when(refreshTokenService.findValidToken("old-refresh-token"))
                .thenReturn(Optional.of(existingToken));
        when(refreshTokenService.createToken(user))
                .thenReturn(newToken);
        when(jwtTokenService.generateToken(any(SecurityUser.class)))
                .thenReturn("new-access-token");

        AuthResponse response = authService.refresh("old-refresh-token");

        assertThat(response.getAccessToken()).isEqualTo("new-access-token");
        assertThat(response.getRefreshToken()).isEqualTo("new-refresh-token");
        assertThat(response.getTokenType()).isEqualTo("Bearer");

        verify(refreshTokenService).findValidToken("old-refresh-token");
        verify(refreshTokenService).revoke(existingToken);
        verify(refreshTokenService).createToken(user);
        verify(jwtTokenService).generateToken(any(SecurityUser.class));
        verifyNoMoreInteractions(authenticationManager, userService, jwtTokenService, refreshTokenService);
    }

    @Test
    void refresh_shouldThrowApiException_whenRefreshTokenIsInvalid() {
        when(refreshTokenService.findValidToken("invalid-token"))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.refresh("invalid-token"))
                .isInstanceOf(ApiException.class)
                .satisfies(ex -> {
                    ApiException apiEx = (ApiException) ex;
                    assertThat(apiEx.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
                    assertThat(apiEx.getErrorCode()).isEqualTo(ErrorCode.INVALID_REFRESH_TOKEN);
                });

        verify(refreshTokenService).findValidToken("invalid-token");
        verifyNoMoreInteractions(authenticationManager, userService, jwtTokenService, refreshTokenService);
    }
}