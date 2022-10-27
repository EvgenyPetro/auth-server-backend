package ru.petrov.authserverback.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class HelloController {

    @GetMapping("/")
    public String hello(){
        return "Hello";
    }

    @GetMapping("/user")
    public String helloUser(Principal principal){
        return "Hello " + principal.getName();
    }

    @PreAuthorize("hasAuthority('ADMIN')")
    @GetMapping("/admin")
    public String helloAdmin(Principal principal){
        return "Hello admin " + principal.getName();
    }
}
