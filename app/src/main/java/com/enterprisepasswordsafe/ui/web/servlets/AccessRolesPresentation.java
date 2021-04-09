package com.enterprisepasswordsafe.ui.web.servlets;

import com.enterprisepasswordsafe.model.AccessRoles;

/**
 * Details of how Access Roles are presented
 */

public enum AccessRolesPresentation {

    USER_HISTORY("view the password history", "ouh_", "uh_", AccessRoles.HISTORYVIEWER_ROLE),
    USER_RA_APPROVER("approved restricted access requests", "our_", "ur_", AccessRoles.APPROVER_ROLE),
    GROUP_HISTORY("view the password history", "ogh_", "gh_", AccessRoles.HISTORYVIEWER_ROLE),
    GROUP_RA_APPROVER("approved restricted access requests", "ogr_", "gr_", AccessRoles.APPROVER_ROLE);

    public final String description;
    public final String uiPrefixForOld;
    public final String uiPrefixForNew;
    public final String internalRoleIdentifier;


    AccessRolesPresentation(String description, String uiPrefixForOld, String uiPrefixForNew, String internalRoleIdentifier) {
        this.description = description;
        this.uiPrefixForOld = uiPrefixForOld;
        this.uiPrefixForNew = uiPrefixForNew;
        this.internalRoleIdentifier = internalRoleIdentifier;
    }
}
