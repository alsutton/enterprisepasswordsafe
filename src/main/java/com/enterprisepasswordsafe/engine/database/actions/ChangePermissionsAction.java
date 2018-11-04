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

package com.enterprisepasswordsafe.engine.database.actions;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.enterprisepasswordsafe.engine.accesscontrol.*;
import com.enterprisepasswordsafe.engine.database.*;

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
    private final Map<User,PasswordPermission> uPerms = new HashMap<>();

    /**
     * The group permissions to set.
     */
    private final Map<Group,PasswordPermission> gPerms = new HashMap<>();

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
    		throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
        this.adminGroup = adminGroup;

        new HierarchyNodePermissionDAO().getDefaultPermissionsForNodeIncludingInherited(
                node.getParentId(), userPermissions, groupPermissions);

        UserDAO uDAO = UserDAO.getInstance();
        for(Map.Entry<String, PasswordPermission> thisEntry : userPermissions.entrySet()) {
        	String id = thisEntry.getKey();
        	User user = uDAO.getByIdDecrypted(id, adminGroup);
        	uPerms.put(user, thisEntry.getValue());
        }

        User adminUser = uDAO.getAdminUser(adminGroup);
        GroupDAO gDAO = GroupDAO.getInstance();
        for(Map.Entry<String, PasswordPermission> thisEntry : groupPermissions.entrySet()) {
        	String id = thisEntry.getKey();
        	Group group = gDAO.getByIdDecrypted(id, adminUser);
        	gPerms.put(group, thisEntry.getValue());
        }
    }

    /**
     * @see NodeObjectAction#process(com.enterprisepasswordsafe.engine.database.HierarchyNode, com.enterprisepasswordsafe.engine.database.AccessControledObject)
     */

    @Override
	public final void process(final HierarchyNode node, final AccessControledObject aco)
        throws GeneralSecurityException, SQLException, UnsupportedEncodingException {
        Password password = (Password) aco;
        AccessControl ac = GroupAccessControlDAO.getInstance().getGac(adminGroup, password);
        if(ac == null) {
            Logger.getAnonymousLogger().log(Level.SEVERE, "No admin GAC for "+password);
            return;
        }

        AccessControlDAO.getInstance().deleteAllForItem(aco);

        UserAccessControlDAO uacDAO = UserAccessControlDAO.getInstance();
        for(Map.Entry<User,PasswordPermission> thisPermission : uPerms.entrySet()) {
        	User user = thisPermission.getKey();

        	AccessControlBuilder<UserAccessControl> uac =
                    UserAccessControl.builder().withAccessorId(user.getId())
                    .withItemId(password.getId()).withReadKey(ac.getReadKey());
        	if (thisPermission.getValue() == PasswordPermission.MODIFY) {
        	    uac.withModifyKey(ac.getModifyKey());
        	}

        	uacDAO.write(uac.build(), user);
        }

        GroupAccessControlDAO gacDAO = GroupAccessControlDAO.getInstance();
        for(Map.Entry<Group,PasswordPermission> thisPermission : gPerms.entrySet()) {
        	Group group = thisPermission.getKey();

            AccessControlBuilder<GroupAccessControl> gac =
                    GroupAccessControl.builder().withAccessorId(group.getId())
                            .withItemId(password.getId()).withReadKey(ac.getReadKey());
            if(thisPermission.getValue() == PasswordPermission.MODIFY) {
                gac.withModifyKey(ac.getModifyKey());
        	}

        	gacDAO.write(group, gac.build());
        }

        BOMFactory.getCurrentConntection().commit();
    }
}
