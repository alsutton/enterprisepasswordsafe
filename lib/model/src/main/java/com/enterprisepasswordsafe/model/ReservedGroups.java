package com.enterprisepasswordsafe.model;

import com.enterprisepasswordsafe.model.persisted.Group;

import java.util.List;

public enum ReservedGroups {
    ADMIN(0L),
    SUBADMIN(1L),
    ALL_USERS(2L),
    NON_VIEWING(3L);

    private Long id;

    ReservedGroups(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }

    public boolean matches(Group g) {
         return id == g.getId();
    }

    public static boolean isSystemGroup(Group g) {
        return g.getId() <= NON_VIEWING.id;
    }

    public static List<ReservedGroups> getPriviledgedGroups() {
        return List.of(ADMIN, SUBADMIN);
    }
}
