package ru.petrov.authserverback.security.oauth2;

import ru.petrov.authserverback.security.VkTokenResponseConverter;

import java.util.Map;

public class VkOauthUserInfo extends OAuth2UserInfo {

    public VkOauthUserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return attributes.get("id").toString();
    }

    @Override
    public String getFirstName() {
        return (String) attributes.get("first_name");
    }

    @Override
    public String getLastName() {
        return (String) attributes.get("last_name");
    }

    @Override
    public String getEmail() {
        String email = VkTokenResponseConverter.getEmail();
        if (email != null) {
            return email;
        }
        return attributes.get("id").toString();
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("photo_max");
    }
}
