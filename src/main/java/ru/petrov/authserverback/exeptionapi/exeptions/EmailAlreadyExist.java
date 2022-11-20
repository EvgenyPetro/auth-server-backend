package ru.petrov.authserverback.exeptionapi.exeptions;

public class EmailAlreadyExist extends RuntimeException{
    public EmailAlreadyExist() {
    }

    public EmailAlreadyExist(String message) {
        super(message);
    }

    public EmailAlreadyExist(String message, Throwable cause) {
        super(message, cause);
    }

    public EmailAlreadyExist(Throwable cause) {
        super(cause);
    }


}
