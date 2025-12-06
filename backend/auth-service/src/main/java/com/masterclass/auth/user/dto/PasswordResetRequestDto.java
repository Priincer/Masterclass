package com.masterclass.auth.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PasswordResetRequestDto {

    @NotBlank(message = "Email must not be blank")
    @Email(message = "Must be a valid email")
    private String email;
}