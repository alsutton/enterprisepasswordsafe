package com.enterprisepasswordsafe.passwordprocessor;

public class PasswordProcessorException extends RuntimeException {

    public PasswordProcessorException(String message) {
        super(message);
    }

    public PasswordProcessorException(String message, Exception reason) {
        super(message, reason);
    }
}
