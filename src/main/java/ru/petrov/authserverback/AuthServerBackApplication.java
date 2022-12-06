package ru.petrov.authserverback;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.petrov.authserverback.entitys.Role;
import ru.petrov.authserverback.entitys.User;
import ru.petrov.authserverback.repositories.RoleRepository;
import ru.petrov.authserverback.repositories.UserRepository;

import java.util.ArrayList;

@SpringBootApplication
public class AuthServerBackApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServerBackApplication.class, args);
    }

//    @Bean
//    public CommandLineRunner run(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
//        return args -> {
//            userRepository.deleteAll();
//            roleRepository.deleteAll();
//
//            User admin = new User(null,
//                    "bill",
//                    "jeyn",
//                    "bill",
//                    passwordEncoder.encode("12345678"),
//                    new ArrayList<>());
//            User user = new User(null,
//                    "bill1",
//                    "jeyn1",
//                    "bill1",
//                    passwordEncoder.encode("12345678"),
//                    new ArrayList<>());
//
//            Role adminRole = new Role(null, "ADMIN");
//            Role userRole = new Role(null, "USER");
//
//            roleRepository.save(adminRole);
//            roleRepository.save(userRole);
//
//            admin.getUserRoles().add(adminRole);
//            user.getUserRoles().add(userRole);
//
//            userRepository.save(admin);
//            userRepository.save(user);
//
//
//        };
//    }
}
