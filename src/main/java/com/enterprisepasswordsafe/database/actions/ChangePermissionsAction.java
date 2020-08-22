/*
 * Copyright (c) 2017 Carbon Security Ltd. <opensource@carbonsecurity.co.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package com.enterprisepasswordsafe.database.actions;

import com.enterprisepasswordsafe.database.AccessControlDAO;
import com.enterprisepasswordsafe.database.AccessControledObject;
import com.enterprisepasswordsafe.database.BOMFactory;
import com.enterprisepasswordsafe.database.Group;
import com.enterprisepasswordsafe.database.GroupAccessControlDAO;
import com.enterprisepasswordsafe.database.GroupDAO;
import com.enterprisepasswordsafe.database.HierarchyNode;
import com.enterprisepasswordsafe.database.HierarchyNodePermissionDAO;
import com.enterprisepasswordsafe.database.Password;
import com.enterprisepasswordsafe.database.UserAccessControlDAO;
import com.enterprisepasswordsafe.database.UserDAO;
import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.engine.accesscontrol.PasswordPermission;
import com.enterprisepasswordsafe.engine.permissions.PermissionSetter;

import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * PasswordAction to handle changing permissions on a password.
 */
public class ChangePermissionsAction implements NodeObjectAction {

    /**
     * The system admin group.
     */

    private final Group adminGroup;

    /**
     * The user permissions to set.
     */
    private final Map<String,PasswordPermission> userPermissions;

    /**
     * The group permissions to set.
     */
    private final Map<String,PasswordPermission> groupPermissions;

    /**
     * Constructor. Stores the user performing the search and the search chain
     * to be matched.
     *
     * @param adminGroup The admin group to use to change the password.
     * @param node The node at which the permissions are being set
     * @param userPermissions The user permissions to set.
     * @param groupPermissions The group permissions to set.
     */

    public ChangePermissionsAction(final Group adminGroup, final HierarchyNode node,
                                   final Map<String,PasswordPermission> userPermissions,
                                   final Map<String,PasswordPermission> groupPermissions)
    		throws SQLException, GeneralSecurityException {
        this.adminGroup = adminGroup;

        new HierarchyNodePermissionDAO().getDefaultPermissionsForNodeIncludingInherited(
                node.getParentId(), userPermissions, groupPermissions);
        this.userPermissions = Map.copyOf(userPermissions);
        this.groupPermissions = Map.copyOf(groupPermissions);
    }

    /**
     * @see NodeObjectAction#process(HierarchyNode, AccessControledObject)
     */

    @Override
	public final void process(final HierarchyNode node, final AccessControledObject aco)
        throws GeneralSecurityException, SQLException {
        Password password = (Password) aco;
        AccessControl ac = GroupAccessControlDAO.getInstance().get(adminGroup, password);
        if(ac == null) {
            Logger.getAnonymousLogger().log(Level.SEVERE, "No admin GAC for "+password);
            return;
        }

        AccessControlDAO.getInstance().deleteAllForItem(aco);

        PermissionSetter permissionSetter =
                new PermissionSetter(
                        UserDAO.getInstance(),
                        GroupDAO.getInstance(),
                        UserAccessControlDAO.getInstance(),
                        GroupAccessControlDAO.getInstance(),
                        adminGroup);
        permissionSetter.storeUserPermissions(ac, password, userPermissions, true);
        permissionSetter.storeGroupPermissions(ac, password, groupPermissions, true);

        BOMFactory.getCurrentConntection().commit();
    }
}
