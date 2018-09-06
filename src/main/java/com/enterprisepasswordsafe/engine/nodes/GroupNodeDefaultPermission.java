package com.enterprisepasswordsafe.engine.nodes;


import com.enterprisepasswordsafe.engine.database.Group;
import com.enterprisepasswordsafe.proguard.JavaBean;

/**
 * Class holding the details of the default permissions a group has for a node
 */

public class GroupNodeDefaultPermission
        implements JavaBean {
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
