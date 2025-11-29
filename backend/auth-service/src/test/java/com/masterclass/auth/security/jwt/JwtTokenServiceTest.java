package com.masterclass.auth.security.jwt;

import com.masterclass.auth.security.config.JwtProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

class JwtTokenServiceTest {

    private JwtTokenService jwtTokenService;
    private UserDetails userDetails;

    @BeforeEach
    void setup() {
        JwtProperties props = new JwtProperties();
        props.setSecret("Fg3keRvQPIG54S/voN6Xj8ydifItzHbCgujHIwz6EiE="); // dein Base64-Secret
        props.setExpirationMillis(3_600_000L); // 1 Stunde

        jwtTokenService = new JwtTokenService(props);
        jwtTokenService.init(); // Key aus dem Secret erzeugen

        userDetails = User.withUsername("test@example.com")
                .password("pw")
                .authorities(Collections.emptyList())
                .build();
    }

    @Test
    void generateToken_shouldContainCorrectSubject() {
        String token = jwtTokenService.generateToken(userDetails);

        String username = jwtTokenService.extractUsername(token);

        assertThat(username).isEqualTo("test@example.com");
    }

    @Test
    void isTokenValid_shouldReturnTrueForCorrectEmail() {
        String token = jwtTokenService.generateToken(userDetails);

        boolean valid = jwtTokenService.isTokenValid(token, "test@example.com");

        assertThat(valid).isTrue();
    }

    @Test
    void isTokenValid_shouldReturnFalseForWrongEmail() {
        String token = jwtTokenService.generateToken(userDetails);

        boolean valid = jwtTokenService.isTokenValid(token, "other@example.com");

        assertThat(valid).isFalse();
    }
}