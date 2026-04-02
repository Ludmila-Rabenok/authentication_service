package com.example.authenticationservice.dto.request;

import jakarta.validation.constraints.NotBlank;

public record RegisterRequestDto(
        @NotBlank(message = "Login cannot be empty")
        String login,
        @NotBlank(message = "Password cannot be empty")
        String password,
        @NotBlank(message = "Role cannot be empty")
        String role) {
}
