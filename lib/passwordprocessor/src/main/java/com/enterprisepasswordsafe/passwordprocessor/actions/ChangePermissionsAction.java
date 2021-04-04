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

package com.enterprisepasswordsafe.passwordprocessor.actions;

import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.PasswordPermission;
import com.enterprisepasswordsafe.model.dao.PasswordAccessControlDAO;
import com.enterprisepasswordsafe.model.persisted.AbstractActor;
import com.enterprisepasswordsafe.model.persisted.Group;
import com.enterprisepasswordsafe.model.persisted.Password;
import com.enterprisepasswordsafe.model.persisted.PasswordAccessControl;
import com.enterprisepasswordsafe.model.persisted.User;
import com.enterprisepasswordsafe.passwordprocessor.PasswordProcessorException;

import java.security.GeneralSecurityException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * PasswordAction to handle changing permissions on a password.
 */
public class ChangePermissionsAction implements PasswordAction {

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
     * @param userPermissions The user permissions to set.
     * @param groupPermissions The group permissions to set.
     */

    public ChangePermissionsAction(final DAORepository daoRepository, final Group adminGroup,
                                   final Map<User,PasswordPermission> userPermissions,
                                   final Map<Group,PasswordPermission> groupPermissions) {
        this.daoRepository = daoRepository;
        this.adminGroup = adminGroup;
        this.userPermissions = Map.copyOf(userPermissions);
        this.groupPermissions = Map.copyOf(groupPermissions);
    }

    /**
     * @see PasswordAction#process(Password)
     */

    @Override
	public final void process(final Password password) throws PasswordProcessorException {
        PasswordAccessControlDAO pacDAO = daoRepository.getPasswordAccessControlDAO();
        PasswordAccessControl ac = pacDAO.getDirectAccessControl(adminGroup, password);
        if(ac == null) {
            Logger.getAnonymousLogger().log(Level.SEVERE, "No admin GAC for "+password);
            return;
        }

        final Set<AbstractActor> actorsWithoutPermissions =
                new HashSet<>(password.getAccessControls().keySet());

        try {
            for (Map.Entry<User, PasswordPermission> entry : userPermissions.entrySet()) {
                actorsWithoutPermissions.remove(entry.getKey());
                setPermission(pacDAO, ac, entry.getKey(), password, entry.getValue());
            }
            for (Map.Entry<Group, PasswordPermission> entry : groupPermissions.entrySet()) {
                actorsWithoutPermissions.remove(entry.getKey());
                setPermission(pacDAO, ac, entry.getKey(), password, entry.getValue());
            }
        } catch (GeneralSecurityException e) {
            throw new PasswordProcessorException("Internal Exception", e);
        }

        // Remove all the users who no longer have explicit access.
        Map<AbstractActor,PasswordAccessControl> permissionMap = password.getAccessControls();
        actorsWithoutPermissions.forEach(permissionMap::remove);
    }

    /**
     * Store the permission for a given actor
     *
     * @param pacDAO the PasswordAccessControlDAO to use for operations
     * @param masterAccessControl the access control which contains the cryptographic keys needed.
     * @param actor the actor we're operating on.
     * @param password the password we're operating on.
     * @param permission the permission to set.
     */
    private void setPermission(PasswordAccessControlDAO pacDAO, PasswordAccessControl masterAccessControl,
                               AbstractActor actor, Password password, PasswordPermission permission)
            throws GeneralSecurityException {
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
