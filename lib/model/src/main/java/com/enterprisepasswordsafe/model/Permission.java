package com.enterprisepasswordsafe.model;

public enum Permission {
    ALLOW("A"),
    DENY("D"),
    APPLY_DEFAULT(null);

    private String representation;

    Permission(String representation) {
        this.representation = representation;
    }

    public String getRepresentation() {
        return representation;
    }

    public boolean isEnforceable() {
        return this == ALLOW || this == DENY;
    }

    public static Permission fromRepresentation(String representation) {
        if(representation == null) {
            return APPLY_DEFAULT;
        }

        for(Permission permission : Permission.values()) {
            if(permission.getRepresentation().equals(representation)) {
                return permission;
            }
        }

        throw new IllegalArgumentException("Unable to find representation for "+representation);
    }
}
