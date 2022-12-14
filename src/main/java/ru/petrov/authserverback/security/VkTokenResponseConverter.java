package ru.petrov.authserverback.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import java.util.HashMap;
import java.util.Map;

public class VkTokenResponseConverter implements Converter<Map<String, Object>, OAuth2AccessTokenResponse> {
    private static Map<String, Object> map = new HashMap<>();

    @Override
    public OAuth2AccessTokenResponse convert(Map<String, Object> source) {

        String accessToken = source.get(OAuth2ParameterNames.ACCESS_TOKEN).toString();
        OAuth2AccessToken.TokenType tokenType = OAuth2AccessToken.TokenType.BEARER;

        Map<String, Object> additionalParameters = new HashMap<>(source);
        map.put("email", source.get("email"));

        return OAuth2AccessTokenResponse.withToken(accessToken)
                .tokenType(tokenType)
                .additionalParameters(additionalParameters)
                .build();
    }

    public static String getEmail() {
        return (String) map.get("email");
    }

}
