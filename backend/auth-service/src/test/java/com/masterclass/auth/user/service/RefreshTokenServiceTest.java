package com.masterclass.auth.user.service;

import com.masterclass.auth.security.config.JwtProperties;
import com.masterclass.auth.user.domain.RefreshToken;
import com.masterclass.auth.user.domain.Role;
import com.masterclass.auth.user.domain.User;
import com.masterclass.auth.user.repository.RefreshTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.mockito.AdditionalAnswers.returnsFirstArg;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private JwtProperties jwtProperties;

    @InjectMocks
    private RefreshTokenService refreshTokenService;

    private User user;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .id(1L)
                .email("refresh@test.com")
                .password("encoded")
                .firstName("Refresh")
                .lastName("User")
                .roles(Set.of(Role.USER))
                .build();
        // kein Stubbing von jwtProperties hier → verhindert UnnecessaryStubbingException
    }

    @Test
    void createForUser_shouldRevokeExistingTokensAndCreateNewToken() {
        // jwtProperties-Stubbing nur hier, wo createToken() es auch wirklich nutzt
        when(jwtProperties.getRefreshExpirationMillis())
                .thenReturn(30L * 24 * 60 * 60 * 1000);

        // repository.save(...) soll das gleiche Objekt zurückgeben, das reingeht
        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(returnsFirstArg());

        RefreshToken created = refreshTokenService.createToken(user);

        assertThat(created.getUser()).isEqualTo(user);
        assertThat(created.isRevoked()).isFalse();
        assertThat(created.getToken()).isNotBlank();
        assertThat(created.getCreatedAt()).isNotNull();
        assertThat(created.getExpiresAt()).isAfter(created.getCreatedAt());

        // 1) Alte aktive Tokens für diesen User revoken
        verify(refreshTokenRepository).revokeAllActiveTokensForUser(eq(user), any(Instant.class));
        // 2) Neuen Token speichern
        verify(refreshTokenRepository).save(any(RefreshToken.class));
        verifyNoMoreInteractions(refreshTokenRepository);
    }

    @Test
    void findValidToken_shouldReturnToken_whenNotRevokedAndNotExpired() {
        Instant now = Instant.now();
        RefreshToken token = RefreshToken.builder()
                .id(10L)
                .token("valid-token")
                .user(user)
                .createdAt(now.minusSeconds(60))
                .expiresAt(now.plusSeconds(60))
                .revoked(false)
                .build();

        when(refreshTokenRepository.findByToken("valid-token"))
                .thenReturn(Optional.of(token));

        Optional<RefreshToken> result = refreshTokenService.findValidToken("valid-token");

        assertThat(result).isPresent();
        assertThat(result.get()).isEqualTo(token);
        verify(refreshTokenRepository).findByToken("valid-token");
    }

    @Test
    void findValidToken_shouldReturnEmpty_whenTokenIsRevoked() {
        Instant now = Instant.now();
        RefreshToken token = RefreshToken.builder()
                .token("revoked-token")
                .user(user)
                .createdAt(now.minusSeconds(60))
                .expiresAt(now.plusSeconds(60))
                .revoked(true)
                .build();

        when(refreshTokenRepository.findByToken("revoked-token"))
                .thenReturn(Optional.of(token));

        Optional<RefreshToken> result = refreshTokenService.findValidToken("revoked-token");

        assertThat(result).isEmpty();
        verify(refreshTokenRepository).findByToken("revoked-token");
    }

    @Test
    void findValidToken_shouldReturnEmpty_whenTokenIsExpired() {
        Instant now = Instant.now();
        RefreshToken token = RefreshToken.builder()
                .token("expired-token")
                .user(user)
                .createdAt(now.minusSeconds(3600))
                .expiresAt(now.minusSeconds(10))
                .revoked(false)
                .build();

        when(refreshTokenRepository.findByToken("expired-token"))
                .thenReturn(Optional.of(token));

        Optional<RefreshToken> result = refreshTokenService.findValidToken("expired-token");

        assertThat(result).isEmpty();
        verify(refreshTokenRepository).findByToken("expired-token");
    }

    @Test
    void revoke_shouldSetRevokedTrueAndSave_whenNotAlreadyRevoked() {
        Instant now = Instant.now();
        RefreshToken token = RefreshToken.builder()
                .token("to-revoke")
                .user(user)
                .createdAt(now)
                .expiresAt(now.plusSeconds(60))
                .revoked(false)
                .build();

        // save als Echo
        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(returnsFirstArg());

        refreshTokenService.revoke(token);

        assertThat(token.isRevoked()).isTrue();

        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(captor.capture());
        RefreshToken saved = captor.getValue();
        assertThat(saved.isRevoked()).isTrue();
    }

    @Test
    void revoke_shouldDoNothing_whenAlreadyRevoked() {
        Instant now = Instant.now();
        RefreshToken token = RefreshToken.builder()
                .token("already-revoked")
                .user(user)
                .createdAt(now)
                .expiresAt(now.plusSeconds(60))
                .revoked(true)
                .build();

        refreshTokenService.revoke(token);

        // kein weiterer DB-Call
        verifyNoInteractions(refreshTokenRepository);
    }

    @Test
    void revokeAllForUser_shouldDelegateToRepository() {
        refreshTokenService.revokeAllForUser(user);

        verify(refreshTokenRepository).revokeAllActiveTokensForUser(eq(user), any(Instant.class));
        verifyNoMoreInteractions(refreshTokenRepository);
    }

    @Test
    void deleteExpiredTokens_shouldReturnNumberOfDeletedRows() {
        when(refreshTokenRepository.deleteAllExpiredSince(any(Instant.class)))
                .thenReturn(5);

        int deleted = refreshTokenService.deleteExpiredTokens();

        assertThat(deleted).isEqualTo(5);
        verify(refreshTokenRepository).deleteAllExpiredSince(any(Instant.class));
        verifyNoMoreInteractions(refreshTokenRepository);
    }
}