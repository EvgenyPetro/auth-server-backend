package ru.petrov.authserverback.services;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ru.petrov.authserverback.entitys.Role;
import ru.petrov.authserverback.entitys.User;
import ru.petrov.authserverback.exeptionapi.exeptions.EmailAlreadyExist;
import ru.petrov.authserverback.model.SecurityUserDetails;
import ru.petrov.authserverback.model.SignUpRequest;
import ru.petrov.authserverback.repositories.UserRepository;

import java.util.ArrayList;
import java.util.List;


@Service
@RequiredArgsConstructor
@Slf4j
public class SecureUserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository
                .findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException(String.format("User {} not found", email)));
        log.info("User auth: {}", user.getId());

        return new SecurityUserDetails(user.getId(),
                user.getEmail(),
                user.getPassword(),
                user.getUserRoles().stream().map((r)
                        -> new SimpleGrantedAuthority(r.getRoleName())).toList());
    }

    public User createUser(SignUpRequest signUpRequest) {

        User user = new User(null, signUpRequest.firstName(),
                signUpRequest.lastName(),
                signUpRequest.username(),
                passwordEncoder.encode(signUpRequest.password()),
                "",
                new ArrayList<>());
        user.getUserRoles().add(new Role(2, "USER"));

        try {
            User saveUser = userRepository.save(user);
            log.info("Create User: {}", saveUser.getId());
            return saveUser;
        } catch (Exception exception) {
            log.error("Created user failure: {}", exception.getMessage());
            throw new EmailAlreadyExist("Email already exist");
        }

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
