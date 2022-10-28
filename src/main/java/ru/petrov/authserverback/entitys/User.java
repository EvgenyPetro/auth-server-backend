package ru.petrov.authserverback.entitys;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class User {

    private String id;
    private String firstName;
    private String lastName;
    private String username;
    private String password;
    private List<GrantedAuthority> userRole;


}
