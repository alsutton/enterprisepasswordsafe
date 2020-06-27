package com.enterprisepasswordsafe.engine.nodes;

import com.enterprisepasswordsafe.engine.database.derived.UserSummary;

/**
 * Class holding the details of the default permissions a user has for a node
 */

public class UserNodeDefaultPermission {
    private final UserSummary user;
    private final String permission;


    public UserNodeDefaultPermission(final UserSummary user, final String permission) {
        this.user = user;
        this.permission = permission;
    }


    public UserSummary getUser() {
        return user;
    }
    public String getPermission() {
        return permission;
    }
}
