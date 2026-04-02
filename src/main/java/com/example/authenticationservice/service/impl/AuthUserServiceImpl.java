package com.example.authenticationservice.service.impl;

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
import com.example.authenticationservice.exception.UserAlreadyExistsException;
import com.example.authenticationservice.exception.UserNotFoundException;
import com.example.authenticationservice.repository.AuthUserRepository;
import com.example.authenticationservice.service.AuthUserService;
import com.example.authenticationservice.service.TokenService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthUserServiceImpl implements AuthUserService {

  private final AuthUserRepository repository;
  private final TokenService tokenService;
  private final BCryptPasswordEncoder passwordEncoder;

  public AuthUserServiceImpl(AuthUserRepository repository,
                             TokenService tokenService, BCryptPasswordEncoder passwordEncoder) {
    this.repository = repository;
    this.tokenService = tokenService;
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  @Transactional
  public RegisterResponseDto register(RegisterRequestDto request) {
    if (repository.findByLogin(request.login()).isPresent()) {
      throw new UserAlreadyExistsException(request.login());
    }
    AuthUser user = new AuthUser();
    user.setLogin(request.login());
    user.setPasswordHash(passwordEncoder.encode(request.password()));
    user.setRole(Role.fromString(request.role()));
    AuthUser saved = repository.save(user);
    return new RegisterResponseDto(saved.getId());
  }

  @Override
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

  @Override
  public AccessTokenResponseDto refresh(RefreshRequestDto request) {
    String refreshToken = request.refreshToken();
    tokenService.validateRefreshTokenOrThrow(refreshToken);
    Long userId = tokenService.getUserId(refreshToken);
    String role = tokenService.getRole(refreshToken);
    String newAccess = tokenService.generateAccessToken(userId, role);
    return new AccessTokenResponseDto(newAccess);
  }

  @Override
  public ValidateResponseDto validate(ValidateRequestDto request) {
    String accessToken = request.accessToken();
    tokenService.validateAccessTokenOrThrow(accessToken);
    Long userId = tokenService.getUserId(accessToken);
    String role = tokenService.getRole(accessToken);
    return new ValidateResponseDto(userId, role);
  }
}