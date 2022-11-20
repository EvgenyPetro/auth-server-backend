package ru.petrov.authserverback.exeptionapi.http;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import ru.petrov.authserverback.exeptionapi.exeptions.EmailAlreadyExist;

import javax.servlet.http.HttpServletRequest;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CONFLICT;

@RestControllerAdvice
@Slf4j
public class GlobalControllerExceptionHandler {

    @ResponseStatus(CONFLICT)
    @ExceptionHandler(EmailAlreadyExist.class)
    public @ResponseBody
    HttpErrorInfo handleBadRequestExceptions(HttpServletRequest request, EmailAlreadyExist ex) {
        return createHttpErrorInfo(CONFLICT, request, ex);
    }

    @ResponseStatus(BAD_REQUEST)
    @ExceptionHandler(UsernameNotFoundException.class)
    @ResponseBody
    public HttpErrorInfo handleUsernameNotFoundException(Exception ex, HttpServletRequest request) {
        return createHttpErrorInfo(BAD_REQUEST, request, ex);
    }


    private HttpErrorInfo createHttpErrorInfo(HttpStatus httpStatus, HttpServletRequest request, Exception ex) {
        final String path = request.getRequestURI();
        final String message = ex.getMessage();

        log.debug("Returning HTTP status: {} for path: {}, message: {}", httpStatus, path, message);
        return new HttpErrorInfo(httpStatus, path, message);
    }
}
