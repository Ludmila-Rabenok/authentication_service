package com.example.authenticationservice.service;

import com.example.authenticationservice.dto.request.LoginRequestDto;
import com.example.authenticationservice.dto.request.RefreshRequestDto;
import com.example.authenticationservice.dto.request.RegisterRequestDto;
import com.example.authenticationservice.dto.request.ValidateRequestDto;
import com.example.authenticationservice.dto.response.AccessTokenResponseDto;
import com.example.authenticationservice.dto.response.RegisterResponseDto;
import com.example.authenticationservice.dto.response.TokenResponseDto;
import com.example.authenticationservice.dto.response.ValidateResponseDto;

/**
 * Service responsible for user authentication and token lifecycle management.
 * <p>
 * Provides operations for user registration, login, token refreshing and
 * access token validation.
 */
public interface AuthUserService {

  /**
   * Registers a new user in the system.
   *
   * @param request DTO containing login, password and role of the new user
   * @return DTO containing the ID of the newly created user
   * @throws UserAlreadyExistsException if a user with the same login already exists
   */
  RegisterResponseDto register(RegisterRequestDto request);

  /**
   * Authenticates a user using login and password and generates a pair of tokens.
   *
   * @param request DTO containing login and password
   * @return DTO containing access and refresh tokens
   * @throws UserNotFoundException       if no user with the given login exists
   * @throws InvalidCredentialsException if the provided password is incorrect
   */
  TokenResponseDto login(LoginRequestDto request);

  /**
   * Generates a new access token using a valid refresh token.
   *
   * @param request DTO containing the refresh token
   * @return DTO containing a newly generated access token
   * @throws InvalidTokenException if the refresh token is invalid, expired or malformed
   */
  AccessTokenResponseDto refresh(RefreshRequestDto request);

  /**
   * Validates an access token and extracts user information from it.
   *
   * @param request DTO containing the access token
   * @return DTO containing user ID and role extracted from the token
   * @throws InvalidTokenException if the access token is invalid, expired or malformed
   */
  ValidateResponseDto validate(ValidateRequestDto request);
}