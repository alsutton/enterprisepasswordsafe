package com.enterprisepasswordsafe.model;

import com.enterprisepasswordsafe.model.persisted.User;

public enum ReservedUsers {
    ADMIN(0L);

    private Long id;

    ReservedUsers(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }

    public boolean matches(User user) {
        return user != null && user.getId() == id;
    }

}
