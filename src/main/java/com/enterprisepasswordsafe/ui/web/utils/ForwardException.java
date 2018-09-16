package com.enterprisepasswordsafe.ui.web.utils;

public class ForwardException extends Throwable {

    private String destination;

    public ForwardException(String destination) {
        this.destination = destination;
    }

    public String getDestination() {
        return destination;
    }
}
