package ru.petrov.authserverback.security;

import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;

import java.util.function.BiConsumer;
import java.util.function.Consumer;

public final class SocialConfigurer extends AbstractHttpConfigurer<SocialConfigurer, HttpSecurity> {

    private String loginPageUrl = "/login";

    private String authorizationRequestUri;

    private Consumer<OAuth2User> oauth2UserHandler;
    private BiConsumer<OAuth2User, Authentication> bioauth2UserHandler;

    private Consumer<OidcUser> oidcUserHandler;

    public SocialConfigurer loginPageUrl(String loginPageUrl) {
        Assert.hasText(loginPageUrl, "loginPageUrl cannot be empty");
        this.loginPageUrl = loginPageUrl;
        return this;
    }

    public SocialConfigurer authorizationRequestUri(String authorizationRequestUri) {
        Assert.hasText(authorizationRequestUri, "authorizationRequestUri cannot be empty");
        this.authorizationRequestUri = authorizationRequestUri;
        return this;
    }

    public SocialConfigurer oauth2UserHandler(UserRepositoryOAuth2UserHandler oauth2UserHandler) {
        Assert.notNull(oauth2UserHandler, "oauth2UserHandler cannot be null");
        this.bioauth2UserHandler = oauth2UserHandler;
        return this;
    }

    public SocialConfigurer oidcUserHandler(Consumer<OidcUser> oidcUserHandler) {
        Assert.notNull(oidcUserHandler, "oidcUserHandler cannot be null");
        this.oidcUserHandler = oidcUserHandler;
        return this;
    }

    @Override
    public void init(HttpSecurity builder) throws Exception {
        ApplicationContext applicationContext = builder.getSharedObject(ApplicationContext.class);
        ClientRegistrationRepository clientRegistrationRepository
                = applicationContext.getBean(ClientRegistrationRepository.class);
        SocialAuthenticationEntryPoint authenticationEntryPoint =
                new SocialAuthenticationEntryPoint(loginPageUrl, clientRegistrationRepository);
        CustomOAuth2AccessTokenResponseClient customOAuth2AccessTokenResponseClient =
                new CustomOAuth2AccessTokenResponseClient();

        if (this.authorizationRequestUri != null) {
            authenticationEntryPoint.setAuthorizationRequestUri(authorizationRequestUri);
        }
        SocialAuthenticationSuccessHandler authenticationSuccessHandler =
                new SocialAuthenticationSuccessHandler();

        if (bioauth2UserHandler != null) {
            authenticationSuccessHandler.setAuth2UserAuthenticationBiConsumer(bioauth2UserHandler);
        }

        builder
                .exceptionHandling(eh -> eh.authenticationEntryPoint(authenticationEntryPoint))
                .oauth2Login(oAuth2Login -> {
                    oAuth2Login.successHandler(authenticationSuccessHandler);
                    if (authorizationRequestUri != null) {
                        String baseUrl = authorizationRequestUri.replace("/{registrationId}", "");
                        oAuth2Login.authorizationEndpoint(ep -> ep.baseUri(baseUrl));
                    }
                    oAuth2Login.tokenEndpoint().accessTokenResponseClient(customOAuth2AccessTokenResponseClient.accessTokenResponseClient())
                            .and()
                            .userInfoEndpoint().userService(new CustomOAuth2UserService())
                    ;

                });

        super.init(builder);
    }
}
