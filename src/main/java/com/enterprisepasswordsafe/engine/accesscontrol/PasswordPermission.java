package com.enterprisepasswordsafe.engine.accesscontrol;

public enum PasswordPermission {
    NONE(false, false, 'N', "0", "N"),
    READ(true, false, 'V', "1", "R"),
    MODIFY(true, true, 'M', "2", "RM");

    public boolean allowsRead, allowsModification;
    private char charRepresentation;
    private String[] stringRepresentations;

    PasswordPermission(boolean allowsRead, boolean allowsModification,
                       char charRepresentation, String... stringRepresentations) {
        this.allowsRead = allowsRead;
        this.allowsModification = allowsModification;
        this.charRepresentation = charRepresentation;
        this.stringRepresentations = stringRepresentations;
    }

    public String toString() {
        return stringRepresentations[0];
    }

    public static PasswordPermission fromRepresentation(char c) {
        for (PasswordPermission permission: values()) {
            if(permission.charRepresentation == c) {
                return permission;
            }
        }
        return null;
    }

    public static PasswordPermission fromRepresentation(String string) {
        if (string == null) {
            return NONE;
        }

        for (PasswordPermission permission: values()) {
            for (String thisRepresentation : permission.stringRepresentations) {
                if (thisRepresentation.equals(string)) {
                    return permission;
                }
            }
        }
        return null;
    }
}
