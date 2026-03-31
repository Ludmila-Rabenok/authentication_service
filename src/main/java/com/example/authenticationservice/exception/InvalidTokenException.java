package com.example.authenticationservice.exception;

import org.springframework.http.HttpStatus;

public class InvalidTokenException extends RuntimeException {

  private final TokenError error;

  public InvalidTokenException(TokenError error) {
    this.error = error;
  }

  @Override
  public String getMessage() {
    return switch (error) {
      case INVALID_SIGNATURE -> "Invalid token signature";
      case MALFORMED -> "Malformed token";
      case EMPTY -> "Token is empty";
      case EXPIRED -> "Token expired";
      case UNSUPPORTED -> "Unsupported token format";
    };
  }

  public HttpStatus getStatus() {
    return switch (error) {
      case EMPTY -> HttpStatus.BAD_REQUEST;
      default -> HttpStatus.UNAUTHORIZED;
    };
  }
}