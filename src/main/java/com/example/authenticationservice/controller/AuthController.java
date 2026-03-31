package com.example.authenticationservice.controller;

import com.example.authenticationservice.dto.request.LoginRequestDto;
import com.example.authenticationservice.dto.request.RefreshRequestDto;
import com.example.authenticationservice.dto.request.RegisterRequestDto;
import com.example.authenticationservice.dto.request.ValidateRequestDto;
import com.example.authenticationservice.dto.response.AccessTokenResponseDto;
import com.example.authenticationservice.dto.response.RegisterResponseDto;
import com.example.authenticationservice.dto.response.TokenResponseDto;
import com.example.authenticationservice.dto.response.ValidateResponseDto;
import com.example.authenticationservice.service.impl.AuthUserServiceImpl;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller responsible for user authentication operations.
 * <p>
 * Provides endpoints for registration, login, token refreshing and token validation.
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

  private final AuthUserServiceImpl authUserService;

  public AuthController(AuthUserServiceImpl authUserService) {
    this.authUserService = authUserService;
  }

  /**
   * Registers a new user.
   *
   * @param request registration data (login, password, role)
   * @return ID of the newly created user
   */
  @PostMapping("/register")
  public ResponseEntity<RegisterResponseDto> register(@Valid @RequestBody RegisterRequestDto request) {
    RegisterResponseDto response = authUserService.register(request);
    return ResponseEntity.ok(response);
  }

  /**
   * Authenticates a user and returns access/refresh tokens.
   *
   * @param request login and password
   * @return access and refresh tokens
   */
  @PostMapping("/login")
  public ResponseEntity<TokenResponseDto> login(@Valid @RequestBody LoginRequestDto request) {
    TokenResponseDto response = authUserService.login(request);
    return ResponseEntity.ok(response);
  }

  /**
   * Generates a new access token using a valid refresh token.
   *
   * @param request refresh token
   * @return newly generated access token
   */
  @PostMapping("/refresh")
  public ResponseEntity<AccessTokenResponseDto> refresh(@Valid @RequestBody RefreshRequestDto request) {
    AccessTokenResponseDto response = authUserService.refresh(request);
    return ResponseEntity.ok(response);
  }

  /**
   * Validates an access token and returns user information.
   *
   * @param request access token
   * @return user ID and role extracted from the token
   */
  @PostMapping("/validate")
  public ResponseEntity<ValidateResponseDto> validate(@Valid @RequestBody ValidateRequestDto request) {
    ValidateResponseDto response = authUserService.validate(request);
    return ResponseEntity.ok(response);
  }
}