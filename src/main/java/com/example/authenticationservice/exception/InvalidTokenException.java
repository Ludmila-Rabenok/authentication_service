package com.example.authenticationservice.exception;

public class InvalidTokenException extends RuntimeException{
  public InvalidTokenException() {
    super("Token is invalid or expired");
  }
}