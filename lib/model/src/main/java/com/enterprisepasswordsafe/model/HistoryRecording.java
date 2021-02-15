package com.enterprisepasswordsafe.model;

public enum HistoryRecording {
    FULL("F"),
    NONE("L"),
    CREATOR_CHOOSES("C");

    private String representation;

    HistoryRecording(String representation) {
        this.representation = representation;
    }

    public String toString() {
        return representation;
    }
}
