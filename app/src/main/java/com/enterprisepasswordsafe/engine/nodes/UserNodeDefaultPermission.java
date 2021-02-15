package com.enterprisepasswordsafe.engine.nodes;

import com.enterprisepasswordsafe.database.derived.AbstractUserSummary;
import com.enterprisepasswordsafe.database.derived.ImmutableUserSummary;

/**
 * Class holding the details of the default permissions a user has for a node
 */

public class UserNodeDefaultPermission {
    private final AbstractUserSummary user;
    private final String permission;


    public UserNodeDefaultPermission(final AbstractUserSummary user, final String permission) {
        this.user = user;
        this.permission = permission;
    }


    public AbstractUserSummary getUser() {
        return user;
    }
    public String getPermission() {
        return permission;
    }
}
