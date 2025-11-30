package com.masterclass.auth.user.repository;

import com.masterclass.auth.user.domain.RefreshToken;
import com.masterclass.auth.user.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    @Modifying
    @Query("""
           update RefreshToken rt
           set rt.revoked = true
           where rt.user = :user
             and rt.revoked = false
             and rt.expiresAt > :now
           """)
    int revokeAllActiveTokensForUser(
            @Param("user") User user,
            @Param("now") Instant now
    );

    @Modifying
    @Query("""
           delete from RefreshToken rt
           where rt.expiresAt < :now
           """)
    int deleteAllExpiredSince(@Param("now") Instant now);
}