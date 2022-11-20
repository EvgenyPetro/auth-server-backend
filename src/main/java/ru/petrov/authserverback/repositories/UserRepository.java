package ru.petrov.authserverback.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.petrov.authserverback.entitys.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {

    Optional<User> findUserByUsername(String username);

    boolean existsUserByUsername(String username);
}
