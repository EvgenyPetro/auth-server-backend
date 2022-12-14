package ru.petrov.authserverback.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.StringUtils;
import ru.petrov.authserverback.entitys.Role;
import ru.petrov.authserverback.entitys.User;
import ru.petrov.authserverback.repositories.UserRepository;
import ru.petrov.authserverback.security.oauth2.OAuth2UserInfo;
import ru.petrov.authserverback.security.oauth2.OAuth2UserInfoFactory;

import java.util.ArrayList;
import java.util.Optional;
import java.util.function.BiConsumer;

@RequiredArgsConstructor
public final class UserRepositoryOAuth2UserHandler implements BiConsumer<OAuth2User, Authentication> {

    private final UserRepository userRepository;

    @Override
    public void accept(OAuth2User oAuth2User, Authentication authentication) {

        String registrationId = ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId();
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId, oAuth2User.getAttributes());

        if (!StringUtils.hasText(oAuth2UserInfo.getEmail())) {
            throw new RuntimeException("Email not found from OAuth2 provider");
        }

        Optional<User> userOptional = userRepository.findByEmail(oAuth2UserInfo.getEmail());

        User user;

        if (userOptional.isPresent()) {
            user = userOptional.get();
            updateExistUser(user, oAuth2UserInfo);
        } else {
            registerNewUser(oAuth2UserInfo);
        }


    }

    private void updateExistUser(User existingUser, OAuth2UserInfo oAuth2UserInfo) {

        existingUser.setFirstName(oAuth2UserInfo.getFirstName());
        existingUser.setLastName(oAuth2UserInfo.getLastName());
        existingUser.setAvatar(oAuth2UserInfo.getImageUrl());

        userRepository.save(existingUser);
    }

    private void registerNewUser(OAuth2UserInfo oAuth2UserInfo) {

        User user = User.builder()
                .id(oAuth2UserInfo.getId())
                .firstName(oAuth2UserInfo.getFirstName())
                .lastName(oAuth2UserInfo.getLastName())
                .email(oAuth2UserInfo.getEmail())
                .avatar(oAuth2UserInfo.getImageUrl())
                .userRoles(new ArrayList<>())
                .build();

        user.getUserRoles().add(new Role(2, "USER"));

        userRepository.save(user);

    }
}