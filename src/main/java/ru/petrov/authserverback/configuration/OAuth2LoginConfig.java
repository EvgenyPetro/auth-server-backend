package ru.petrov.authserverback.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Component;

@Component
public class OAuth2LoginConfig {

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(vkClientRegistration(), google(), github());
    }

    private ClientRegistration google(){
        return CommonOAuth2Provider.GOOGLE.getBuilder("google")
                .clientId("773056160900-f7mfjvrn2gdcr8s59j6heqr1fdmi5d67.apps.googleusercontent.com")
                .clientSecret("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")
                .build();

    }

    private ClientRegistration github(){
        return CommonOAuth2Provider.GITHUB.getBuilder("github")
                .clientId("b97dda3e789594a729a5")
                .clientSecret("325bc223eaaff5c6f5da933cf74774a5655fd773")
                .build();

    }

    private ClientRegistration vkClientRegistration() {
        return ClientRegistration.withRegistrationId("vk")
                .clientId("51498282")
                .clientSecret("aDlpVrcpafksEJSHQFmM")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
                .scope("2", "email", "phone")
                .authorizationUri("https://oauth.vk.com/authorize")
                .tokenUri("https://oauth.vk.com/access_token")
                .userInfoUri("https://api.vk.com/method/users.get?&v=5.131&fields=photo_max,contacts")
                .userNameAttributeName("id")
                .build();
    }
}
