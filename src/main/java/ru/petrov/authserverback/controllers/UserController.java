package ru.petrov.authserverback.controllers;


import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import ru.petrov.authserverback.model.SignUpRequest;
import ru.petrov.authserverback.repositories.UserRepository;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserRepository repository;

    @PostMapping("api/v1/create-user")
    public ResponseEntity<?> createUser(@RequestBody SignUpRequest signUpRequest) {
        return ResponseEntity.status(HttpStatus.CREATED).body(repository.createUser(signUpRequest));
    }

    @PreAuthorize("hasAuthority('ADMIN')")
    @GetMapping("api/v1/users")
    public ResponseEntity<?> findAll() {
        return ResponseEntity.status(HttpStatus.OK).body(repository.findAllUser());
    }

    @PreAuthorize("hasAuthority('ADMIN')")
    @DeleteMapping("api/v1/user/{id}")
    public ResponseEntity<?> createUser(@PathVariable String id) {
        return ResponseEntity.status(HttpStatus.OK).body(repository.deleteUser(id));
    }
}