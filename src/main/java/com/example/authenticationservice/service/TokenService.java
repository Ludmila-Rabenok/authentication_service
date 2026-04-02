package com.example.authenticationservice.service;

/**
 * Service responsible for generating, validating and parsing JWT tokens.
 * <p>
 * Provides operations for creating access and refresh tokens, validating
 * their integrity and extracting user-related information from them.
 */
public interface TokenService {

  /**
   * Generates a signed JWT access token for the given user.
   *
   * @param userId ID of the authenticated user
   * @param role   role of the user (e.g. ADMIN, USER)
   * @return signed JWT access token
   */
  String generateAccessToken(Long userId, String role);

  /**
   * Generates a signed JWT refresh token for the given user.
   *
   * @param userId ID of the authenticated user
   * @param role   role of the user
   * @return signed JWT refresh token
   */
  String generateRefreshToken(Long userId, String role);

  /**
   * Validates the provided refresh JWT token and throws an exception if it is invalid.
   * <p>
   * This method checks token signature, expiration time, structure, supported format and token type.
   *
   * @param token JWT refresh token to validate
   * @throws InvalidTokenException if the token is expired, malformed,
   *                               has an invalid signature, is unsupported,
   *                               is empty or has an incorrect token type
   */
  void validateRefreshTokenOrThrow(String token);

  /**
   * Validates the provided access JWT token and throws an exception if it is invalid.
   * <p>
   * This method checks token signature, expiration time, structure, supported format and token type.
   *
   * @param token JWT access token to validate
   * @throws InvalidTokenException if the token is expired, malformed,
   *                               has an invalid signature, is unsupported,
   *                               is empty or has an incorrect token type
   */
  void validateAccessTokenOrThrow(String token);

  /**
   * Extracts the user ID from a valid JWT token.
   *
   * @param token JWT token
   * @return user ID stored in the token
   * @throws InvalidTokenException if the token is invalid
   */
  Long getUserId(String token);

  /**
   * Extracts the user role from a valid JWT token.
   *
   * @param token JWT token
   * @return user role stored in the token
   * @throws InvalidTokenException if the token is invalid
   */
  String getRole(String token);
}