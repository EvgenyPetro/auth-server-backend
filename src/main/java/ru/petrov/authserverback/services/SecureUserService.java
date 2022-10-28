package ru.petrov.authserverback.services;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import ru.petrov.authserverback.repositories.UserRepository;
import ru.petrov.authserverback.entitys.User;
import ru.petrov.authserverback.model.SecureUser;


@Service
@RequiredArgsConstructor
public class SecureUserService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findUserByUsername(username);
        return new SecureUser(user);
    }
}
