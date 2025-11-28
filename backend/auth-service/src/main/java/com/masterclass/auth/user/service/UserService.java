package com.masterclass.auth.user.service;

import com.masterclass.auth.common.api.ErrorCode;
import com.masterclass.auth.common.exception.ApiException;
import com.masterclass.auth.user.domain.Role;
import com.masterclass.auth.user.domain.User;
import com.masterclass.auth.user.dto.RegisterRequest;
import com.masterclass.auth.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public User registerUser(RegisterRequest request) {
        if (userRepository.findByEmail(request.email()).isPresent()) {
            throw new ApiException(
                    HttpStatus.BAD_REQUEST,
                    ErrorCode.EMAIL_ALREADY_IN_USE,
                    "Email already in use: " + request.email()
            );
        }

        User user = User.builder()
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .firstName(request.firstName())
                .lastName(request.lastName())
                .roles(Set.of(Role.USER))
                .build();

        return userRepository.save(user);
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }
}