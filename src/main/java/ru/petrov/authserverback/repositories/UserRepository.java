package ru.petrov.authserverback.repositories;

import ru.petrov.authserverback.entitys.User;
import ru.petrov.authserverback.model.SignUpRequest;

import java.util.List;

public interface UserRepository {

    User createUser(SignUpRequest signUpRequest);
    boolean deleteUser(String id);
    List<User> findAllUser();
    User findUserByUsername(String username);

}
