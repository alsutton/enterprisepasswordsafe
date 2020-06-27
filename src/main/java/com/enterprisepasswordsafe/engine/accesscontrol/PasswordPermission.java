package com.enterprisepasswordsafe.engine.accesscontrol;

public enum PasswordPermission {
    NONE(false, false, 'N', "0", "N"),
    READ(true, false, 'V', "1", "R"),
    MODIFY(true, true, 'M', "2", "RM");

    public final boolean allowsRead;
    public final boolean allowsModification;
    private final char charRepresentation;
    private final String[] stringRepresentations;

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
            if(matches(permission, string)) {
                return permission;
            }
        }
        return null;
    }

    private static boolean matches(PasswordPermission permission, String representation) {
        for (String thisRepresentation : permission.stringRepresentations) {
            if (thisRepresentation.equals(representation)) {
                return true;
            }
        }

        return false;
    }
}
