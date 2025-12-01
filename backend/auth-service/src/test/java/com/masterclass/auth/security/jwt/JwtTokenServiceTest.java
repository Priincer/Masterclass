package com.masterclass.auth.security.jwt;

import com.masterclass.auth.security.config.JwtProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import javax.crypto.KeyGenerator;
import java.util.Base64;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

class JwtTokenServiceTest {

    private JwtTokenService jwtTokenService;
    private UserDetails userDetails;

    @BeforeEach
    void setup() throws Exception {
        // Sicheren, zufälligen 256-bit Schlüssel generieren
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
        keyGen.init(256);
        byte[] rawKey = keyGen.generateKey().getEncoded();
        String base64Key = Base64.getEncoder().encodeToString(rawKey);

        JwtProperties props = new JwtProperties();
        props.setSecret(base64Key);
        props.setExpirationMillis(3_600_000L);

        jwtTokenService = new JwtTokenService(props);
        jwtTokenService.init(); // Schlüssel bauen

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