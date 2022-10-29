package ru.petrov.authserverback.utils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Component
@Slf4j
public class JwtTokenTokenProviderJjwt implements JwtTokenProvider {

    public static final String jwtAccessSecret = "AccessSecret";
    public static final String jwtRefreshSecret = "RefreshSecret";
    public static final int jwtAccessExpiration = 24;
    public static final int jwtRefreshExpiration = 24 * 30;


    @Override
    public String generatedJwtAccessToken(Authentication authentication) {
        return generatedJwtToken(authentication, jwtAccessExpiration, jwtAccessSecret);
    }

    @Override
    public String generatedJwtRefreshToken(Authentication authentication) {
        return generatedJwtToken(authentication, jwtRefreshExpiration, jwtRefreshSecret);
    }

    @Override
    public User verifyAccessToken(String token) {
        return verifyToken(token, jwtAccessSecret);
    }

    @Override
    public User verifyRefreshToken(String token) {
        return verifyToken(token, jwtRefreshSecret);
    }

    private User verifyToken(String token, String jwtSecret) {

        Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
        String user = claims.getSubject();

        var roles = claims.get("roles");
        var collection = new ObjectMapper()
                .convertValue(roles,
                        new TypeReference<ArrayList<HashMap<String, String>>>() {
                        });

        ArrayList<GrantedAuthority> authorities = new ArrayList<>();
        collection.forEach(map -> map.values().forEach(s -> authorities.add(new SimpleGrantedAuthority(s))));

        return new User(user, "", authorities);


    }

    private String generatedJwtToken(Authentication authentication, int jwtExpiration, String jwtSecret) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setSubject(authentication.getName())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plus(jwtExpiration, ChronoUnit.HOURS)))
                .claim("roles", authentication.getAuthorities())
                .signWith(SignatureAlgorithm.HS256, jwtSecret)
                .setId(UUID.randomUUID().toString())
                .compact();
    }

    private boolean validateToken(String jwtToken) {
        Jwts.parser().setSigningKey(jwtAccessSecret).parseClaimsJws(jwtToken);
        return true;
    }

}
