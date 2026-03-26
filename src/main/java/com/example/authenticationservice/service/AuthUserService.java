package com.example.authenticationservice.service;

import com.example.authenticationservice.dto.request.LoginRequestDto;
import com.example.authenticationservice.dto.request.RefreshRequestDto;
import com.example.authenticationservice.dto.request.RegisterRequestDto;
import com.example.authenticationservice.dto.request.ValidateRequestDto;
import com.example.authenticationservice.dto.response.AccessTokenResponseDto;
import com.example.authenticationservice.dto.response.RegisterResponseDto;
import com.example.authenticationservice.dto.response.TokenResponseDto;
import com.example.authenticationservice.dto.response.ValidateResponseDto;
import com.example.authenticationservice.entity.AuthUser;
import com.example.authenticationservice.entity.Role;
import com.example.authenticationservice.exception.InvalidCredentialsException;
import com.example.authenticationservice.exception.InvalidTokenException;
import com.example.authenticationservice.exception.UserAlreadyExistsException;
import com.example.authenticationservice.exception.UserNotFoundException;
import com.example.authenticationservice.repository.AuthUserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthUserService {

  private final AuthUserRepository repository;
  private final TokenService tokenService;
  private final BCryptPasswordEncoder passwordEncoder;

  public AuthUserService(AuthUserRepository repository,
                         TokenService tokenService) {
    this.repository = repository;
    this.tokenService = tokenService;
    this.passwordEncoder = new BCryptPasswordEncoder();
  }

  @Transactional
  public RegisterResponseDto register(RegisterRequestDto request) {
    if (repository.findByLogin(request.login()).isPresent()) {
      throw new UserAlreadyExistsException(request.login());
    }
    AuthUser user = new AuthUser();
    user.setLogin(request.login());
    user.setPasswordHash(passwordEncoder.encode(request.password()));
    user.setRole(Role.valueOf(request.role()));
    AuthUser saved = repository.save(user);
    return new RegisterResponseDto(saved.getId());
  }

  public TokenResponseDto login(LoginRequestDto request) {
    AuthUser user = repository.findByLogin(request.login())
            .orElseThrow(() -> new UserNotFoundException(request.login()));
    if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
      throw new InvalidCredentialsException();
    }
    String access = tokenService.generateAccessToken(user.getId(), user.getRole().name());
    String refresh = tokenService.generateRefreshToken(user.getId(), user.getRole().name());
    return new TokenResponseDto(access, refresh);
  }

  public AccessTokenResponseDto refresh(RefreshRequestDto request) {
    String refreshToken = request.refreshToken();
    if (!tokenService.isTokenValid(refreshToken)) {
      throw new InvalidTokenException();
    }
    Long userId = tokenService.getUserId(refreshToken);
    String role = tokenService.getRole(refreshToken);
    String newAccess = tokenService.generateAccessToken(userId, role);
    return new AccessTokenResponseDto(newAccess);
  }

  public ValidateResponseDto validate(ValidateRequestDto request) {
    String accessToken = request.accessToken();
    if (!tokenService.isTokenValid(accessToken)) {
      throw new InvalidTokenException();
    }
    Long userId = tokenService.getUserId(accessToken);
    String role = tokenService.getRole(accessToken);
    return new ValidateResponseDto(userId, role);
  }
}
