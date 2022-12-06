package ru.petrov.authserverback.configuration;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;
import ru.petrov.authserverback.utils.JwtTokenProvider;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class Oauth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JwtTokenProvider tokenProvider;


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {

        clearAuthenticationAttributes(request);

        String jwtAccessToken = tokenProvider.generatedJwtAccessToken(authentication);
        String jwtRefreshToken = tokenProvider.generatedJwtRefreshToken(authentication);

        String targetUrl = UriComponentsBuilder.fromUriString("http://localhost:3000/login")
                .queryParam("access_token", jwtAccessToken)
                .queryParam("refresh_token", jwtRefreshToken)
                .build().toUriString();
        getRedirectStrategy().sendRedirect(request, response, targetUrl);

    }


}
