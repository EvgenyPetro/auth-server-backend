package ru.petrov.authserverback.repositories;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;
import ru.petrov.authserverback.entitys.User;
import ru.petrov.authserverback.model.SignUpRequest;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.List;

@Repository
public class UserRepositoryInMemory implements UserRepository {

    @Autowired
    private PasswordEncoder encoder;
    private final List<User> USER_DATABASE = new ArrayList<>();

    @PostConstruct
    private void createdDB() {
        USER_DATABASE.add(new User("1", "Billi1", "Wong1", "billi1", encoder.encode("12345678"), List.of(new SimpleGrantedAuthority("ADMIN"))));
        USER_DATABASE.add(new User("2", "Billi2", "Wong2", "billi2", encoder.encode("12345678"), List.of(new SimpleGrantedAuthority("USER"), new SimpleGrantedAuthority("MANAGER"))));
        USER_DATABASE.add(new User("3", "Billi3", "Wong3", "billi3", encoder.encode("12345678"), List.of(new SimpleGrantedAuthority("USER"))));
    }

    @Override
    public User createUser(SignUpRequest signUpRequest) {

        User newUser = new User(getId(),
                signUpRequest.firstName(),
                signUpRequest.lastName(),
                signUpRequest.username(),
                encoder.encode(signUpRequest.password()),
                List.of(new SimpleGrantedAuthority("USER")));

        USER_DATABASE.add(newUser);
        return newUser;
    }

    @Override
    public boolean deleteUser(String id) {
        User deleteUser = USER_DATABASE.stream()
                .filter(user -> user.getId().equals(id))
                .findFirst()
                .orElseThrow();
        USER_DATABASE.remove(deleteUser);
        return true;
    }

    @Override
    public List<User> findAllUser() {
        return USER_DATABASE;
    }

    @Override
    public User findUserByUsername(String username) {
        return USER_DATABASE.stream().filter(user -> user.getUsername().equals(username)).findFirst().orElseThrow();
    }


    private String getId() {
        return String.valueOf(USER_DATABASE.size() + 1);
    }
}
