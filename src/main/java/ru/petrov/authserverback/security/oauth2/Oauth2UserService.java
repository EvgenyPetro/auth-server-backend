package ru.petrov.authserverback.security.oauth2;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import ru.petrov.authserverback.entitys.Role;
import ru.petrov.authserverback.entitys.User;
import ru.petrov.authserverback.model.SecurityUserDetails;
import ru.petrov.authserverback.repositories.UserRepository;

import java.util.ArrayList;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class Oauth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        try {
            return processOAuth2User(userRequest, oAuth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OidcUser processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(
                oAuth2UserRequest.getClientRegistration().getRegistrationId(),
                oAuth2User.getAttributes());

        if (!StringUtils.hasText(oAuth2UserInfo.getEmail())) {
            throw new RuntimeException("Email not found from OAuth2 provider");
        }

        Optional<User> userOptional = userRepository.findByEmail(oAuth2UserInfo.getEmail());

        User user;

        if (userOptional.isPresent()) {
            user = userOptional.get();

            user = updateExistUser(user, oAuth2UserInfo);
        } else {
            user = registerNewUser(oAuth2UserInfo);
        }

        return SecurityUserDetails.create(user, oAuth2User.getAttributes());
    }

    private User updateExistUser(User existingUser, OAuth2UserInfo oAuth2UserInfo) {

        existingUser.setFirstName(oAuth2UserInfo.getFirstName());
        existingUser.setLastName(oAuth2UserInfo.getLastName());
        existingUser.setAvatar(oAuth2UserInfo.getImageUrl());

        return userRepository.save(existingUser);
    }

    private User registerNewUser(OAuth2UserInfo oAuth2UserInfo) {

        User user = User.builder()
                .id(oAuth2UserInfo.getId())
                .firstName(oAuth2UserInfo.getFirstName())
                .lastName(oAuth2UserInfo.getLastName())
                .email(oAuth2UserInfo.getEmail())
                .avatar(oAuth2UserInfo.getImageUrl())
                .userRoles(new ArrayList<>())
                .build();

        user.getUserRoles().add(new Role(2, "USER"));

        return userRepository.save(user);

    }
}
