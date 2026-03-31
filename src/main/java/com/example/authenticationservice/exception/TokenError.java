package com.example.authenticationservice.exception;

public enum TokenError {
  INVALID_SIGNATURE,
  MALFORMED,
  EMPTY,
  EXPIRED,
  UNSUPPORTED
}