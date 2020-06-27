package com.enterprisepasswordsafe.engine.nodes;

import com.enterprisepasswordsafe.database.Group;

/**
 * Class holding the details of the default permissions a group has for a node
 */

public class GroupNodeDefaultPermission {
    private final Group group;
    private final String permission;


    public GroupNodeDefaultPermission(final Group group, final String permission) {
        this.group = group;
        this.permission = permission;
    }


    public Group getGroup() {
        return group;
    }
    public String getPermission() {
        return permission;
    }
}
