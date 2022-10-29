package ru.petrov.authserverback.utils;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;

public interface JwtTokenProvider {
    String generatedJwtAccessToken(Authentication authentication);
    String generatedJwtRefreshToken(Authentication authentication);
    User verifyAccessToken(String token);
    User verifyRefreshToken(String token);
}
