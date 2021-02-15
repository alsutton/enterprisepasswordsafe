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

import com.enterprisepasswordsafe.model.AccessControledObject;
import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.PasswordPermission;
import com.enterprisepasswordsafe.model.dao.PasswordAccessControlDAO;
import com.enterprisepasswordsafe.model.persisted.AbstractActor;
import com.enterprisepasswordsafe.model.persisted.Group;
import com.enterprisepasswordsafe.model.persisted.HierarchyNode;
import com.enterprisepasswordsafe.model.persisted.Password;
import com.enterprisepasswordsafe.model.persisted.PasswordAccessControl;
import com.enterprisepasswordsafe.model.persisted.User;

import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * PasswordAction to handle changing permissions on a password.
 */
public class ChangePermissionsAction implements NodeObjectAction {

    private final DAORepository daoRepository;

    /**
     * The system admin group.
     */

    private final Group adminGroup;

    /**
     * The user permissions to set.
     */
    private final Map<User, PasswordPermission> userPermissions;

    /**
     * The group permissions to set.
     */
    private final Map<Group, PasswordPermission> groupPermissions;

    /**
     * Constructor. Stores the user performing the search and the search chain
     * to be matched.
     *
     * @param adminGroup The admin group to use to change the password.
     * @param node The node at which the permissions are being set
     * @param userPermissions The user permissions to set.
     * @param groupPermissions The group permissions to set.
     */

    public ChangePermissionsAction(final DAORepository daoRepository,
                                   final Group adminGroup, final HierarchyNode node,
                                   final Map<User,PasswordPermission> userPermissions,
                                   final Map<Group,PasswordPermission> groupPermissions)
    		throws SQLException, GeneralSecurityException {
        this.daoRepository = daoRepository;
        this.adminGroup = adminGroup;
        this.userPermissions = Map.copyOf(userPermissions);
        this.groupPermissions = Map.copyOf(groupPermissions);
    }

    /**
     * @see NodeObjectAction#process(HierarchyNode, AccessControledObject)
     */

    @Override
	public final void process(final HierarchyNode node, final Password password)
        throws GeneralSecurityException, SQLException {
        PasswordAccessControlDAO pacDAO = daoRepository.getPasswordAccessControlDAO();;
        PasswordAccessControl ac = pacDAO.getDirectAccessControl(adminGroup, password);
        if(ac == null) {
            Logger.getAnonymousLogger().log(Level.SEVERE, "No admin GAC for "+password);
            return;
        }

        final Set<AbstractActor> actorsWithoutPermissions =
                Set.copyOf(password.getAccessControls().keySet());
        userPermissions.forEach((key,value) -> {
            actorsWithoutPermissions.remove(key);
            setPermission(pacDAO, ac, key, password, value);
        });
        groupPermissions.forEach((key,value) -> {
            actorsWithoutPermissions.remove(key);
            setPermission(pacDAO, ac, key, password, value);
        });

        // Remove all the users who no longer have explicit access.
        Map<AbstractActor,PasswordAccessControl> permissionMap = password.getAccessControls();
        actorsWithoutPermissions.forEach(actor -> permissionMap.remove(actor));
    }

    /**
     * Store the permission for a given actor
     *
     * @param masterAccessControl
     * @param actor
     * @param password
     * @param permission
     */
    private void setPermission(PasswordAccessControlDAO pacDAO, PasswordAccessControl masterAccessControl,
                               AbstractActor actor, Password password, PasswordPermission permission) {
        Map<AbstractActor, PasswordAccessControl> permissionMap = password.getAccessControls();
        if (permission == PasswordPermission.NONE) {
            permissionMap.remove(actor);
            return;
        }

        PasswordAccessControl accessControl =
                permissionMap.computeIfAbsent(actor, key -> new PasswordAccessControl(key, password));
        accessControl.setReadKey(masterAccessControl.getReadKey());
        if (permission == PasswordPermission.WRITE) {
            accessControl.setModifyKey(masterAccessControl.getModifyKey());
        }
        pacDAO.store(actor, accessControl);
    }
}
