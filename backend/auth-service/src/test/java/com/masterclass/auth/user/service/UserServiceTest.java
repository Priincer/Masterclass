package com.masterclass.auth.user.service;

import com.masterclass.auth.common.api.ErrorCode;
import com.masterclass.auth.common.exception.ApiException;
import com.masterclass.auth.user.domain.Role;
import com.masterclass.auth.user.domain.User;
import com.masterclass.auth.user.dto.RegisterRequest;
import com.masterclass.auth.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    UserRepository userRepository;

    @Mock
    PasswordEncoder passwordEncoder;

    @InjectMocks
    UserService userService;

    @Test
    void registerUser_shouldSaveUser_whenEmailIsFree() {
        // arrange
        RegisterRequest request = RegisterRequest.builder()
                .email("new@example.com")
                .password("plainPW")
                .firstName("Hans")
                .lastName("Peter")
                .build();

        when(userRepository.findByEmail("new@example.com"))
                .thenReturn(Optional.empty());
        when(passwordEncoder.encode("plainPW"))
                .thenReturn("hashedPW");

        User saved = User.builder()
                .id(1L)
                .email("new@example.com")
                .password("hashedPW")
                .firstName("Hans")
                .lastName("Peter")
                .roles(Set.of(Role.USER))
                .build();

        when(userRepository.save(any(User.class))).thenReturn(saved);

        // act
        User result = userService.registerUser(request);

        // assert
        assertEquals(1L, result.getId());
        assertEquals("new@example.com", result.getEmail());
        assertEquals("hashedPW", result.getPassword());
        assertTrue(result.getRoles().contains(Role.USER));

        verify(userRepository).findByEmail("new@example.com");
        verify(userRepository).save(any(User.class));
    }

    @Test
    void registerUser_shouldThrowApiException_whenEmailAlreadyExists() {
        // arrange
        RegisterRequest request = RegisterRequest.builder()
                .email("taken@example.com")
                .password("pw")
                .firstName("Hans")
                .lastName("Peter")
                .build();

        when(userRepository.findByEmail("taken@example.com"))
                .thenReturn(Optional.of(new User()));

        // act
        ApiException ex = assertThrows(ApiException.class,
                () -> userService.registerUser(request));

        // assert
        assertEquals(ErrorCode.EMAIL_ALREADY_IN_USE, ex.getErrorCode());
        assertEquals(HttpStatus.BAD_REQUEST, ex.getStatus());

        verify(userRepository, never()).save(any());
    }
}