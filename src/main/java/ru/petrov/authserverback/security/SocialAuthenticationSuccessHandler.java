package ru.petrov.authserverback.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.function.BiConsumer;

public final class SocialAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final AuthenticationSuccessHandler delegate = new SavedRequestAwareAuthenticationSuccessHandler();

    private BiConsumer<OAuth2User, Authentication> auth2UserAuthenticationBiConsumer = (oAuth2User, authentication) -> {};

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        if (authentication instanceof OAuth2AuthenticationToken) {
            if (authentication.getPrincipal() instanceof OidcUser) {
                auth2UserAuthenticationBiConsumer.accept((OidcUser) authentication.getPrincipal(),authentication);
            } else if (authentication.getPrincipal() instanceof OAuth2User) {
                auth2UserAuthenticationBiConsumer.accept((OAuth2User) authentication.getPrincipal(), authentication);
            }
        }
        delegate.onAuthenticationSuccess(request,response,authentication);
    }

    public void setAuth2UserAuthenticationBiConsumer(BiConsumer<OAuth2User, Authentication> auth2UserAuthenticationBiConsumer) {
        this.auth2UserAuthenticationBiConsumer = auth2UserAuthenticationBiConsumer;
    }
}
