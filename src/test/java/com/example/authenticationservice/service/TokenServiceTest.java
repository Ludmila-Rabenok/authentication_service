package com.example.authenticationservice.service;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenServiceTest {

  private TokenService tokenService;

  @BeforeEach
  void setUp() {
    tokenService = new TokenService(
            "uQ2x8V7p1mJ9kA3sL0fWc9TqZ5rN8yB1vH4eD7tP6gK2mS9xQ8lF3zR7wC5uN0aJ",
            10000,
            20000
    );
  }

  @Test
  void shouldGenerateAndValidateAccessToken() {
    String token = tokenService.generateAccessToken(1L, "ADMIN");

    assertTrue(tokenService.isTokenValid(token));
    assertEquals(1L, tokenService.getUserId(token));
    assertEquals("ADMIN", tokenService.getRole(token));
  }


  @Test
  void shouldFalse_whenInvalidToken() {
    assertFalse(tokenService.isTokenValid("badToken"));
  }

  @Test
  void shouldFalse_whenExpiredToken() throws InterruptedException {
    TokenService tokenServiceBad = new TokenService(
            "uQ2x8V7p1mJ9kA3sL0fWc9TqZ5rN8yB1vH4eD7tP6gK2mS9xQ8lF3zR7wC5uN0aJ",
            0,
            0
    );
    String token = tokenServiceBad.generateAccessToken(1L, "ADMIN");

    assertFalse(tokenServiceBad.isTokenValid(token));
  }
}