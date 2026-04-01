package com.example.authenticationservice.entity;

import com.example.authenticationservice.exception.InvalidRoleException;

public enum Role {
  ADMIN,
  USER;

  public static Role fromString(String value) {
    try {
      return Role.valueOf(value.trim().toUpperCase());
    } catch (Exception e) {
      throw new InvalidRoleException("Invalid role: " + value);
    }
  }
}