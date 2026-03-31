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
import com.example.authenticationservice.exception.UserAlreadyExistsException;
import com.example.authenticationservice.exception.UserNotFoundException;
import com.example.authenticationservice.repository.AuthUserRepository;
import com.example.authenticationservice.service.impl.AuthUserServiceImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthUserServiceImplTest {
  @Mock
  private AuthUserRepository repository;
  @Mock
  private TokenService tokenService;
  @Spy
  private BCryptPasswordEncoder passwordEncoder;
  @InjectMocks
  private AuthUserServiceImpl authUserService;

  @Test
  void register_shouldRegister() {
    RegisterRequestDto request = new RegisterRequestDto("Ivan", "password", "ADMIN");
    AuthUser authUser = new AuthUser();
    authUser.setId(1L);
    when(repository.findByLogin("Ivan")).thenReturn(Optional.empty());
    when(repository.save(any(AuthUser.class))).thenReturn(authUser);

    RegisterResponseDto actual = authUserService.register(request);

    assertEquals(1L, actual.userId());
    verify(repository).save(any(AuthUser.class));
  }

  @Test
  void register_shouldThrowUserAlreadyExists() {
    RegisterRequestDto request = new RegisterRequestDto("Ivan", "password", "ADMIN");

    when(repository.findByLogin("Ivan")).thenReturn(Optional.of(new AuthUser()));

    assertThrows(UserAlreadyExistsException.class,
            () -> authUserService.register(request));
  }

  @Test
  void login_shouldLogin() {
    LoginRequestDto request = new LoginRequestDto("Ivan", "password");
    AuthUser user = new AuthUser();
    user.setId(1L);
    user.setLogin("Ivan");
    user.setPasswordHash(passwordEncoder.encode("password"));
    user.setRole(Role.ADMIN);

    when(repository.findByLogin("Ivan")).thenReturn(Optional.of(user));
    when(tokenService.generateAccessToken(1L, "ADMIN")).thenReturn("access");
    when(tokenService.generateRefreshToken(1L, "ADMIN")).thenReturn("refresh");

    TokenResponseDto actual = authUserService.login(request);

    assertAll(
            () -> assertEquals("access", actual.accessToken()),
            () -> assertEquals("refresh", actual.refreshToken()));
  }

  @Test
  void login_shouldThrowUserNotFound() {
    LoginRequestDto request = new LoginRequestDto("Ivan", "password");
    when(repository.findByLogin("Ivan")).thenReturn(Optional.empty());

    assertThrows(UserNotFoundException.class,
            () -> authUserService.login(request));
  }

  @Test
  void login_shouldThrowInvalidCredentials() {
    LoginRequestDto request = new LoginRequestDto("Ivan", "wrong");
    AuthUser user = new AuthUser();
    user.setPasswordHash(passwordEncoder.encode("password"));

    when(repository.findByLogin("Ivan")).thenReturn(Optional.of(user));

    assertThrows(InvalidCredentialsException.class,
            () -> authUserService.login(request));
  }

  @Test
  void refresh_shouldRefreshToken() {
    RefreshRequestDto request = new RefreshRequestDto("refreshToken");

    doNothing().when(tokenService).validateTokenOrThrow("refreshToken");
    when(tokenService.getUserId("refreshToken")).thenReturn(1L);
    when(tokenService.getRole("refreshToken")).thenReturn("ADMIN");
    when(tokenService.generateAccessToken(1L, "ADMIN")).thenReturn("newAccess");

    AccessTokenResponseDto actual = authUserService.refresh(request);

    assertEquals("newAccess", actual.accessToken());
  }

  @Test
  void validate_shouldValidateToken() {
    ValidateRequestDto request = new ValidateRequestDto("access");
    doNothing().when(tokenService).validateTokenOrThrow("access");
    when(tokenService.getUserId("access")).thenReturn(1L);
    when(tokenService.getRole("access")).thenReturn("ADMIN");

    ValidateResponseDto actual = authUserService.validate(request);

    assertAll(
            () -> assertEquals(1L, actual.userId()),
            () -> assertEquals("ADMIN", actual.role())
    );
  }
}