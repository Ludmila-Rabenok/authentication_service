package com.example.authenticationservice.dto.request;
import jakarta.validation.constraints.NotBlank;

public record RefreshRequestDto(
        @NotBlank (message = "Token cannot be empty")
        String refreshToken) {
}
