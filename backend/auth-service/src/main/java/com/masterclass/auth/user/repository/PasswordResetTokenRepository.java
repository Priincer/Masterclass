package com.masterclass.auth.user.repository;

import com.masterclass.auth.user.domain.PasswordResetToken;
import com.masterclass.auth.user.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {

    Optional<PasswordResetToken> findByToken(String token);

    @Modifying
    @Query("""
           update PasswordResetToken t
           set t.used = true
           where t.user = :user
             and t.used = false
           """)
    int markAllAsUsedForUser(@Param("user") User user);

    @Modifying
    @Query("""
           delete from PasswordResetToken t
           where t.expiresAt < :now
              or t.used = true
           """)
    int deleteAllExpiredOrUsedSince(@Param("now") Instant now);
}