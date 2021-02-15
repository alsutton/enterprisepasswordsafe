package com.enterprisepasswordsafe.model;

public enum EntityState {
    ENABLED(0),
    DISABLED(1),
    DELETED(2);

    private Integer representation;

    EntityState(int representation) {
        this.representation = representation;
    }

    public Integer getRepresentation() {
        return representation;
    }

    public static EntityState fromRepresentation(Integer stateCode) {
        switch (stateCode) {
            case 0:
                return ENABLED;
            case 1:
                return DISABLED;
            case 2:
                return DELETED;
            default:
                throw new IllegalArgumentException("Unknown entity state "+stateCode);
        }
    }
}
