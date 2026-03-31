package com.example.authenticationservice.service.impl;

import com.example.authenticationservice.exception.InvalidTokenException;
import com.example.authenticationservice.exception.TokenError;
import com.example.authenticationservice.service.TokenService;
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

  public String generateAccessToken(Long userId, String role) {
    return buildToken(userId, role, accessTokenExpirationMs);
  }

  public String generateRefreshToken(Long userId, String role) {
    return buildToken(userId, role, refreshTokenExpirationMs);
  }

  private String buildToken(Long userId, String role, long expirationMs) {
    Instant now = Instant.now();
    Instant expiry = now.plusMillis(expirationMs);

    return Jwts.builder()
            .setSubject(String.valueOf(userId))
            .setIssuedAt(Date.from(now))
            .setExpiration(Date.from(expiry))
            .addClaims(Map.of("role", role))
            .signWith(secretKey, SignatureAlgorithm.HS256)
            .compact();
  }

  public void validateTokenOrThrow(String token) {
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

  public Long getUserId(String token) {
    Claims claims = parseClaims(token);
    return Long.valueOf(claims.getSubject());
  }

  public String getRole(String token) {
    Claims claims = parseClaims(token);
    return claims.get("role", String.class);
  }

  private Claims parseClaims(String token) {
    return Jwts.parserBuilder()
            .setSigningKey(secretKey)
            .build()
            .parseClaimsJws(token)
            .getBody();
  }
}