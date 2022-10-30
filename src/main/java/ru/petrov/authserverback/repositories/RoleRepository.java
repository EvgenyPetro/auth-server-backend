package ru.petrov.authserverback.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.petrov.authserverback.entitys.Role;

public interface RoleRepository extends JpaRepository<Role, Integer> {
}
