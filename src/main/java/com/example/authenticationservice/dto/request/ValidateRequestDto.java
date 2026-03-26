package com.example.authenticationservice.dto.request;

import jakarta.validation.constraints.NotBlank;

public record ValidateRequestDto(
        @NotBlank (message = "Token cannot be empty")
        String accessToken) {
}
