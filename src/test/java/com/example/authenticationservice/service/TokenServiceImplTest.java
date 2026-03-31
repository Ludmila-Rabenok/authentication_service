package com.example.authenticationservice.service;


import com.example.authenticationservice.exception.InvalidTokenException;
import com.example.authenticationservice.exception.TokenError;
import com.example.authenticationservice.service.impl.TokenServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TokenServiceImplTest {

  private TokenServiceImpl tokenService;

  @BeforeEach
  void setUp() {
    tokenService = new TokenServiceImpl(
            "uQ2x8V7p1mJ9kA3sL0fWc9TqZ5rN8yB1vH4eD7tP6gK2mS9xQ8lF3zR7wC5uN0aJ",
            10000,
            20000
    );
  }

  @Test
  void shouldGenerateAndValidateAccessToken() {
    String token = tokenService.generateAccessToken(1L, "ADMIN");

    assertDoesNotThrow(() -> tokenService.validateTokenOrThrow(token));
    assertEquals(1L, tokenService.getUserId(token));
    assertEquals("ADMIN", tokenService.getRole(token));
  }


  @Test
  void shouldThrowInvalidTokenException_whenExpiredToken() {
    String expectedMessage = new InvalidTokenException(TokenError.EXPIRED).getMessage();
    TokenServiceImpl service = new TokenServiceImpl(
            "uQ2x8V7p1mJ9kA3sL0fWc9TqZ5rN8yB1vH4eD7tP6gK2mS9xQ8lF3zR7wC5uN0aJ",
            0,
            0
    );
    String token = service.generateAccessToken(1L, "ADMIN");

    String actualMessage = assertThrows(InvalidTokenException.class,
            () -> service.validateTokenOrThrow(token)).getMessage();
    assertEquals(expectedMessage, actualMessage);
  }

  @Test
  void shouldThrowInvalidTokenException_whenTokenEmpty() {
    String expectedMessage = new InvalidTokenException(TokenError.EMPTY).getMessage();

    String actualMessage = assertThrows(InvalidTokenException.class,
            () -> tokenService.validateTokenOrThrow("")).getMessage();
    assertEquals(expectedMessage, actualMessage);
  }

  @Test
  void shouldThrowInvalidTokenException_whenTokenMalformed() {
    String expectedMessage = new InvalidTokenException(TokenError.MALFORMED).getMessage();

    String actualMessage = assertThrows(InvalidTokenException.class,
            () -> tokenService.validateTokenOrThrow("not-a-jwt-token")).getMessage();
    assertEquals(expectedMessage, actualMessage);
  }

  @Test
  void shouldThrowInvalidTokenException_whenTokenUnsupported() {
    String expectedMessage = new InvalidTokenException(TokenError.UNSUPPORTED).getMessage();
    String unsupportedToken = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.";

    String actualMessage = assertThrows(InvalidTokenException.class,
            () -> tokenService.validateTokenOrThrow(unsupportedToken)).getMessage();
    assertEquals(expectedMessage, actualMessage);
  }

  @Test
  void shouldThrowInvalidTokenException_whenSignatureInvalid() {
    String expectedMessage = new InvalidTokenException(TokenError.INVALID_SIGNATURE).getMessage();
    String token = tokenService.generateAccessToken(1L, "ADMIN");
    String tampered = token.substring(0, token.length() - 1) + "X";

    String actualMessage = assertThrows(InvalidTokenException.class,
            () -> tokenService.validateTokenOrThrow(tampered)).getMessage();

    assertEquals(expectedMessage, actualMessage);
  }
}