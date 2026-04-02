package com.example.authenticationservice.dto.response;

public record ValidateResponseDto(
        Long userId,
        String role) {
}
