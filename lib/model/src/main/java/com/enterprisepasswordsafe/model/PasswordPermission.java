package com.enterprisepasswordsafe.model;

public enum PasswordPermission {
    NONE, READ, WRITE;

    public boolean allowsRead() {
        return this == READ || this == WRITE;
    }

    public boolean allowsModification() { return this == WRITE; }
}
