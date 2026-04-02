package com.example.authenticationservice.dto.response;

public record TokenResponseDto(
        String accessToken,
        String refreshToken) {
}
