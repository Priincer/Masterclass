package com.masterclass.auth.user.repository;

import com.masterclass.auth.user.domain.Role;
import com.masterclass.auth.user.domain.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Test
    void shouldSaveUser() {
        User user = User.builder()
                .email("test@example.com")
                .password("secret")
                .firstName("Hans")
                .lastName("Peter")
                .roles(Set.of(Role.USER))
                .build();

        User saved = userRepository.save(user);

        assertNotNull(saved.getId());
        assertEquals("test@example.com", saved.getEmail());
    }

    @Test
    void shouldThrowWhenEmailIsDuplicate() {
        User user1 = User.builder()
                .email("duplicate@example.com")
                .password("secret1")
                .roles(Set.of(Role.USER))
                .build();

        User user2 = User.builder()
                .email("duplicate@example.com")
                .password("secret2")
                .roles(Set.of(Role.USER))
                .build();

        userRepository.save(user1);

        assertThrows(DataIntegrityViolationException.class, () -> {
            userRepository.saveAndFlush(user2);
        });
    }
}