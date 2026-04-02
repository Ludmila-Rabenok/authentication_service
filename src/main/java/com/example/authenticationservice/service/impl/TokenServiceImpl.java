package com.example.authenticationservice.service.impl;

import com.example.authenticationservice.exception.InvalidTokenException;
import com.example.authenticationservice.exception.TokenError;
import com.example.authenticationservice.service.TokenService;
import com.example.authenticationservice.service.token.TokenType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Service
public class TokenServiceImpl implements TokenService {

  private static final String CLAIM_ROLE = "role";
  private static final String CLAIM_TOKEN_TYPE = "token_type";

  private final SecretKey secretKey;
  private final long accessTokenExpirationMs;
  private final long refreshTokenExpirationMs;

  public TokenServiceImpl(
          @Value("${jwt.secret}") String secret,
          @Value("${jwt.access-token-expiration-ms}") long accessTokenExpirationMs,
          @Value("${jwt.refresh-token-expiration-ms}") long refreshTokenExpirationMs
  ) {
    this.secretKey = Keys.hmacShaKeyFor(secret.getBytes());
    this.accessTokenExpirationMs = accessTokenExpirationMs;
    this.refreshTokenExpirationMs = refreshTokenExpirationMs;
  }

  @Override
  public String generateAccessToken(Long userId, String role) {
    return buildToken(userId, role, accessTokenExpirationMs, TokenType.ACCESS);
  }

  @Override
  public String generateRefreshToken(Long userId, String role) {
    return buildToken(userId, role, refreshTokenExpirationMs, TokenType.REFRESH);
  }

  @Override
  public void validateRefreshTokenOrThrow(String token) {
    validateTokenOrThrow(token);
    if (!TokenType.REFRESH.equals(getTokenType(token))) {
      throw new InvalidTokenException(TokenError.INVALID_TOKEN_TYPE);
    }
  }

  @Override
  public void validateAccessTokenOrThrow(String token) {
    validateTokenOrThrow(token);
    if (!TokenType.ACCESS.equals(getTokenType(token))) {
      throw new InvalidTokenException(TokenError.INVALID_TOKEN_TYPE);
    }
  }

  @Override
  public Long getUserId(String token) {
    Claims claims = parseClaims(token);
    return Long.valueOf(claims.getSubject());
  }

  @Override
  public String getRole(String token) {
    Claims claims = parseClaims(token);
    return claims.get(CLAIM_ROLE, String.class);
  }

  private String buildToken(Long userId, String role, long expirationMs, TokenType type) {
    Instant now = Instant.now();
    Instant expiry = now.plusMillis(expirationMs);
    return Jwts.builder()
            .setSubject(String.valueOf(userId))
            .setIssuedAt(Date.from(now))
            .setExpiration(Date.from(expiry))
            .addClaims(Map.of(CLAIM_ROLE, role,
                    CLAIM_TOKEN_TYPE, type.name()))
            .signWith(secretKey, SignatureAlgorithm.HS256)
            .compact();
  }

  private void validateTokenOrThrow(String token) {
    try {
      parseClaims(token);
    } catch (ExpiredJwtException e) {
      throw new InvalidTokenException(TokenError.EXPIRED);
    } catch (SignatureException e) {
      throw new InvalidTokenException(TokenError.INVALID_SIGNATURE);
    } catch (MalformedJwtException e) {
      throw new InvalidTokenException(TokenError.MALFORMED);
    } catch (UnsupportedJwtException e) {
      throw new InvalidTokenException(TokenError.UNSUPPORTED);
    } catch (IllegalArgumentException e) {
      throw new InvalidTokenException(TokenError.EMPTY);
    }
  }

  private TokenType getTokenType(String token) {
    Claims claims = parseClaims(token);
    return TokenType.valueOf(claims.get(CLAIM_TOKEN_TYPE, String.class));
  }

  private Claims parseClaims(String token) {
    return Jwts.parserBuilder()
            .setSigningKey(secretKey)
            .build()
            .parseClaimsJws(token)
            .getBody();
  }
}