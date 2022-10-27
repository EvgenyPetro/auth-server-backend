package ru.petrov.authserverback.entitys;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

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


}
