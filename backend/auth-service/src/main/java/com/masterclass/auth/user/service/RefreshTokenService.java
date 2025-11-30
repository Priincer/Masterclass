package com.masterclass.auth.user.service;

import com.masterclass.auth.security.config.JwtProperties;
import com.masterclass.auth.user.domain.RefreshToken;
import com.masterclass.auth.user.domain.User;
import com.masterclass.auth.user.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtProperties jwtProperties;


    @Transactional
    public RefreshToken createToken(User user) {
        Instant now = Instant.now();
        long refreshExpirationMillis = jwtProperties.getRefreshExpirationMillis();

        refreshTokenRepository.revokeAllActiveTokensForUser(user, now);

        RefreshToken token = RefreshToken.builder()
                .token(UUID.randomUUID().toString())
                .user(user)
                .createdAt(now)
                .expiresAt(now.plusMillis(refreshExpirationMillis))
                .revoked(false)
                .build();

        return refreshTokenRepository.save(token);
    }

    @Transactional(readOnly = true)
    public Optional<RefreshToken> findValidToken(String tokenValue) {
        Instant now = Instant.now();

        return refreshTokenRepository.findByToken(tokenValue)
                .filter(token -> !token.isRevoked())
                .filter(token -> token.getExpiresAt().isAfter(now));
    }

    @Transactional
    public void revoke(RefreshToken token) {
        if (token.isRevoked()) {
            return;
        }
        token.setRevoked(true);
        refreshTokenRepository.save(token);
    }

    @Transactional
    public void revokeAllForUser(User user) {
        Instant now = Instant.now();
        refreshTokenRepository.revokeAllActiveTokensForUser(user, now);
    }

    @Transactional
    public int deleteExpiredTokens() {
        Instant now = Instant.now();
        return refreshTokenRepository.deleteAllExpiredSince(now);
    }
}