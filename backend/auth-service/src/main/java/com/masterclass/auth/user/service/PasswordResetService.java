package com.masterclass.auth.user.service;

import com.masterclass.auth.user.domain.PasswordResetToken;
import com.masterclass.auth.user.domain.User;
import com.masterclass.auth.user.repository.PasswordResetTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private final PasswordResetTokenRepository passwordResetTokenRepository;

    // Konfigurierbare Gültigkeit, default 60 Minuten
    @Value("${security.password-reset.expiration-minutes:60}")
    private long passwordResetExpirationMinutes;

    @Transactional
    public PasswordResetToken createToken(User user) {
        Instant now = Instant.now();

        // alle alten Tokens für den User invalidieren
        passwordResetTokenRepository.markAllAsUsedForUser(user);

        Instant expiresAt = now.plusSeconds(passwordResetExpirationMinutes * 60);

        PasswordResetToken token = PasswordResetToken.builder()
                .token(UUID.randomUUID().toString())
                .user(user)
                .createdAt(now)
                .expiresAt(expiresAt)
                .used(false)
                .build();
        PasswordResetToken saved = passwordResetTokenRepository.save(token);

        log.info("Password reset token for {}: {}", user.getEmail(), saved.getToken());

        return saved;
    }

    @Transactional(readOnly = true)
    public Optional<PasswordResetToken> findValidToken(String tokenValue) {
        Instant now = Instant.now();

        return passwordResetTokenRepository.findByToken(tokenValue)
                .filter(token -> !token.isUsed())
                .filter(token -> token.getExpiresAt().isAfter(now));
    }

    @Transactional
    public void markAsUsed(PasswordResetToken token) {
        if (token.isUsed()) {
            return;
        }
        token.setUsed(true);
        passwordResetTokenRepository.save(token);
    }

    @Transactional
    public int deleteExpiredOrUsedTokens() {
        Instant now = Instant.now();
        return passwordResetTokenRepository.deleteAllExpiredOrUsedSince(now);
    }
}