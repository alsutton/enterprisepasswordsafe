package com.enterprisepasswordsafe.ui.web.utils;

public class RedirectException extends Throwable {

    private final String destination;

    public RedirectException(String destination) {
        this.destination = destination;
    }

    public String getDestination() {
        return destination;
    }
}
