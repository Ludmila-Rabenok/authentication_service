package com.example.authenticationservice.controller;

import com.example.authenticationservice.dto.request.LoginRequestDto;
import com.example.authenticationservice.dto.request.RefreshRequestDto;
import com.example.authenticationservice.dto.request.RegisterRequestDto;
import com.example.authenticationservice.dto.request.ValidateRequestDto;
import com.example.authenticationservice.dto.response.AccessTokenResponseDto;
import com.example.authenticationservice.dto.response.RegisterResponseDto;
import com.example.authenticationservice.dto.response.TokenResponseDto;
import com.example.authenticationservice.dto.response.ValidateResponseDto;
import com.example.authenticationservice.service.AuthUserService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

  private final AuthUserService authUserService;

  public AuthController(AuthUserService authUserService) {
    this.authUserService = authUserService;
  }

  @PostMapping("/register")
  public ResponseEntity<RegisterResponseDto> register(@Valid @RequestBody RegisterRequestDto request) {
    RegisterResponseDto response = authUserService.register(request);
    return ResponseEntity.ok(response);
  }

  @PostMapping("/login")
  public ResponseEntity<TokenResponseDto> login(@Valid @RequestBody LoginRequestDto request) {
    TokenResponseDto response = authUserService.login(request);
    return ResponseEntity.ok(response);
  }

  @PostMapping("/refresh")
  public ResponseEntity<AccessTokenResponseDto> refresh(@Valid @RequestBody RefreshRequestDto request) {
    AccessTokenResponseDto response = authUserService.refresh(request);
    return ResponseEntity.ok(response);
  }

  @PostMapping("/validate")
  public ResponseEntity<ValidateResponseDto> validate(@Valid @RequestBody ValidateRequestDto request) {
    ValidateResponseDto response = authUserService.validate(request);
    return ResponseEntity.ok(response);
  }
}
