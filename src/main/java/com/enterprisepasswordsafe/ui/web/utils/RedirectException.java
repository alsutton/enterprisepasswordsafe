package com.enterprisepasswordsafe.ui.web.utils;

public class RedirectException extends Throwable {

    private String destination;

    public RedirectException(String destination) {
        this.destination = destination;
    }

    public String getDestination() {
        return destination;
    }
}
