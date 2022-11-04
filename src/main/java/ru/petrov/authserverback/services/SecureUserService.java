package ru.petrov.authserverback.services;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ru.petrov.authserverback.entitys.Role;
import ru.petrov.authserverback.entitys.User;
import ru.petrov.authserverback.model.SecureUser;
import ru.petrov.authserverback.model.SignUpRequest;
import ru.petrov.authserverback.repositories.UserRepository;

import java.util.ArrayList;
import java.util.List;


@Service
@RequiredArgsConstructor
public class SecureUserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository
                .findUserByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(String.format("User {} not found", username)));
        return new SecureUser(user);
    }

    public User createUser(SignUpRequest signUpRequest) {
        User user = new User(null, signUpRequest.firstName(),
                signUpRequest.lastName(),
                signUpRequest.username(),
                passwordEncoder.encode(signUpRequest.password()),
                new ArrayList<>());
        user.getUserRoles().add(new Role(2, "USER"));
        return userRepository.save(user);
    }

    public List<User> findAllUser() {
        return userRepository.findAll();
    }

    public boolean deleteUser(String id) {
        boolean present = userRepository.findById(id).isPresent();
        if (present) {
            userRepository.deleteById(id);
            return true;
        }
        return true;
    }
}
