package ru.petrov.authserverback.model;

public record SignUpRequest(String firstName, String lastName, String username, String password) {}
