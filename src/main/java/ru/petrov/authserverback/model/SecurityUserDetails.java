package ru.petrov.authserverback.model;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import ru.petrov.authserverback.entitys.User;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Data
public class SecurityUserDetails implements UserDetails, OidcUser {

    private String id;
    private String email;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;
    private Map<String, Object> attributes;

    public SecurityUserDetails(String id,
                               String email,
                               String password,
                               Collection<? extends GrantedAuthority> authorities) {
        this.email = email;
        this.password = password;
        this.id = id;
        this.authorities = authorities;
    }

    public SecurityUserDetails(String id,
                               String email,
                               String password,
                               Collection<? extends GrantedAuthority> authorities,
                               Map<String, Object> attributes) {
        this.email = email;
        this.password = password;
        this.id = id;
        this.authorities = authorities;
        this.attributes = attributes;
    }

    public static SecurityUserDetails create(User user) {
        List<GrantedAuthority> authorities = Collections.
                singletonList(new SimpleGrantedAuthority("ROLE_USER"));

        return new SecurityUserDetails(
                user.getId(),
                user.getEmail(),
                user.getPassword(),
                authorities
        );
    }

    public static SecurityUserDetails create(User user, Map<String, Object> attributes) {
        SecurityUserDetails userPrincipal = SecurityUserDetails.create(user);
        userPrincipal.setAttributes(attributes);
        return userPrincipal;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public Map<String, Object> getClaims() {
        return null;
    }

    @Override
    public OidcUserInfo getUserInfo() {
        return null;
    }

    @Override
    public OidcIdToken getIdToken() {
        return null;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return id;
    }
}
