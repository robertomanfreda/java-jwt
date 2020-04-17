package com.github.robertomanfreda.java.jwt.exceptions;

public class InvalidTokenException extends Exception {
    public InvalidTokenException(String errorMessage) {
        super(errorMessage);
    }
}
