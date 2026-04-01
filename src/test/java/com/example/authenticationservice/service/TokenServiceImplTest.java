package com.example.authenticationservice.service;


import com.example.authenticationservice.exception.InvalidTokenException;
import com.example.authenticationservice.exception.TokenError;
import com.example.authenticationservice.service.impl.TokenServiceImpl;
import com.example.authenticationservice.service.token.TokenType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TokenServiceImplTest {

  private static final String SECRET = "uQ2x8V7p1mJ9kA3sL0fWc9TqZ5rN8yB1vH4eD7tP6gK2mS9xQ8lF3zR7wC5uN0aJ";

  private TokenServiceImpl tokenService;

  @BeforeEach
  void setUp() {
    tokenService = new TokenServiceImpl(
            SECRET,
            10000,
            20000
    );
  }

  @Test
  void shouldGenerateAndValidateAccessToken() {
    String token = tokenService.generateAccessToken(1L, "ADMIN");

    assertDoesNotThrow(() -> tokenService.validateAccessTokenOrThrow(token));
    assertEquals(1L, tokenService.getUserId(token));
    assertEquals("ADMIN", tokenService.getRole(token));
  }

  @Test
  void shouldGenerateAndValidateRefreshToken() {
    String token = tokenService.generateRefreshToken(1L, "ADMIN");

    assertDoesNotThrow(() -> tokenService.validateRefreshTokenOrThrow(token));
    assertEquals(1L, tokenService.getUserId(token));
    assertEquals("ADMIN", tokenService.getRole(token));
  }

  @ParameterizedTest
  @EnumSource(TokenType.class)
  void shouldThrowInvalidTokenException_whenExpiredToken(TokenType type) {
    String expectedMessage = new InvalidTokenException(TokenError.EXPIRED).getMessage();
    TokenServiceImpl service = new TokenServiceImpl(
            SECRET,
            0,
            0
    );
    String token = switch (type) {
      case ACCESS -> service.generateAccessToken(1L, "ADMIN");
      case REFRESH -> service.generateRefreshToken(1L, "ADMIN");
    };

    String actualMessage = assertThrows(InvalidTokenException.class,
            () -> {
              if (type == TokenType.ACCESS) {
                service.validateAccessTokenOrThrow(token);
              } else {
                service.validateRefreshTokenOrThrow(token);
              }
            }
    ).getMessage();
    assertEquals(expectedMessage, actualMessage);
  }

  @ParameterizedTest
  @EnumSource(TokenType.class)
  void shouldThrowInvalidTokenException_whenTokenEmpty(TokenType type) {
    String expectedMessage = new InvalidTokenException(TokenError.EMPTY).getMessage();

    String actualMessage = assertThrows(InvalidTokenException.class,
            () -> {
              if (type == TokenType.ACCESS) {
                tokenService.validateAccessTokenOrThrow("");
              } else {
                tokenService.validateRefreshTokenOrThrow("");
              }
            }
    ).getMessage();
    assertEquals(expectedMessage, actualMessage);
  }

  @ParameterizedTest
  @EnumSource(TokenType.class)
  void shouldThrowInvalidTokenException_whenTokenMalformed(TokenType type) {
    String expectedMessage = new InvalidTokenException(TokenError.MALFORMED).getMessage();

    String actualMessage = assertThrows(InvalidTokenException.class,
            () -> {
              if (type == TokenType.ACCESS) {
                tokenService.validateAccessTokenOrThrow("not-a-jwt-token");
              } else {
                tokenService.validateRefreshTokenOrThrow("not-a-jwt-token");
              }
            }
    ).getMessage();
    assertEquals(expectedMessage, actualMessage);
  }

  @ParameterizedTest
  @EnumSource(TokenType.class)
  void shouldThrowInvalidTokenException_whenTokenUnsupported(TokenType type) {
    String expectedMessage = new InvalidTokenException(TokenError.UNSUPPORTED).getMessage();
    String unsupportedToken = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.";

    String actualMessage = assertThrows(InvalidTokenException.class,
            () -> {
              if (type == TokenType.ACCESS) {
                tokenService.validateAccessTokenOrThrow(unsupportedToken);
              } else {
                tokenService.validateRefreshTokenOrThrow(unsupportedToken);
              }
            }
    ).getMessage();
    assertEquals(expectedMessage, actualMessage);
  }

  @ParameterizedTest
  @EnumSource(TokenType.class)
  void shouldThrowInvalidTokenException_whenSignatureInvalid(TokenType type) {
    String expectedMessage = new InvalidTokenException(TokenError.INVALID_SIGNATURE).getMessage();
    String token = switch (type) {
      case ACCESS -> tokenService.generateAccessToken(1L, "ADMIN");
      case REFRESH -> tokenService.generateRefreshToken(1L, "ADMIN");
    };
    String tampered = token.substring(0, token.length() - 1) + "X";

    String actualMessage = assertThrows(InvalidTokenException.class,
            () -> {
              if (type == TokenType.ACCESS) {
                tokenService.validateAccessTokenOrThrow(tampered);
              } else {
                tokenService.validateRefreshTokenOrThrow(tampered);
              }
            }
    ).getMessage();
    assertEquals(expectedMessage, actualMessage);
  }
}