package com.masterclass.auth.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;

@Builder
public record RegisterRequest(
        @NotBlank
        @Email
        String email,

        @NotBlank
        String password,

        @NotBlank
        String firstName,

        @NotBlank
        String lastName
) {}