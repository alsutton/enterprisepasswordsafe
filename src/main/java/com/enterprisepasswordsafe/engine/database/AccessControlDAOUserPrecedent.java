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

package com.enterprisepasswordsafe.engine.database;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

/**
 * Data access object for the user access control.
 *
 * @author Compaq_Owner
 */

public final class AccessControlDAOUserPrecedent
	extends AccessControlDAO {

    /**
     * Checks to see if a user has explicit access rights, if they don't
     * check if they have access via a group.
     *
     * @param theUser The user to get the access rights for.
     * @param item The item ID to get the rights for.
     *
     * @return The access control for the user to access the item.
     *
     * @throws GeneralSecurityException Thrown if there is a problem decrypting
     *  the access control data.
     * @throws SQLException Thrown if there is a problem getting the access control
     *  data from the database.
     * @throws UnsupportedEncodingException
     */

    @Override
	public AccessControl getAccessControl(final User theUser, final AccessControledObject item)
        throws GeneralSecurityException, SQLException, UnsupportedEncodingException {
        return getAccessControl(theUser, item.getId());
    }

    /**
     * Checks to see if a user has explicit access rights, if they don't
     * check if they have access via a group.
     *
     * @param theUser The user to get the access rights for.
     * @param itemId The item ID to get the rights for.
     *
     * @return The access control for the user to access the item.
     *
     * @throws GeneralSecurityException Thrown if there is a problem decrypting
     *  the access control data.
     * @throws SQLException Thrown if there is a problem getting the access control
     *  data from the database.
     * @throws UnsupportedEncodingException
     */

    @Override
	public AccessControl getAccessControl(final User theUser, final String itemId)
        throws GeneralSecurityException, SQLException, UnsupportedEncodingException {
        AccessControl ac = UserAccessControlDAO.getInstance().getUac(theUser, itemId);
        if  (ac == null) {
            ac = GroupAccessControlDAO.getInstance().getGac(theUser, itemId);
        }

        return ac;
    }

    /**
     * Checks to see if a user has explicit access rights, if they don't
     * check if they have access via a group.
     *
     * @param theUser The user to get the access rights for.
     * @param itemId The item ID to get the rights for.
     *
     * @return The access control for the user to access the item.
     *
     * @throws GeneralSecurityException Thrown if there is a problem decrypting
     *  the access control data.
     * @throws SQLException Thrown if there is a problem getting the access control
     *  data from the database.
     * @throws UnsupportedEncodingException
     */

    @Override
	public AccessControl getReadAccessControl(final User theUser, final String itemId)
        throws GeneralSecurityException, SQLException, UnsupportedEncodingException {
        AccessControl ac = UserAccessControlDAO.getInstance().getUac(theUser, itemId);
        if  (ac == null) {
            ac = GroupAccessControlDAO.getInstance().getReadGac(theUser, itemId);
        }

        return ac;
    }

    /**
     * Checks to see if a user has explicit access rights, if they don't
     * check if they have access via a group.
     *
     * @param theUser The user to get the access rights for.
     * @param itemId The item ID to get the rights for.
     *
     * @return The access control for the user to access the item.
     *
     * @throws GeneralSecurityException Thrown if there is a problem decrypting
     *  the access control data.
     * @throws SQLException Thrown if there is a problem getting the access control
     *  data from the database.
     * @throws UnsupportedEncodingException
     */

    @Override
	public AccessControl getAccessControlEvenIfDisabled(final User theUser, final String itemId)
        throws GeneralSecurityException, SQLException, UnsupportedEncodingException {
        AccessControl ac = UserAccessControlDAO.getInstance().getUac(theUser, itemId);
        if (ac == null) {
            ac = GroupAccessControlDAO.getInstance().getGacEvenIfDisabled(theUser, itemId);
        }

        return ac;
    }

    /**
     * Delete all the access controls for an item except for the admin group access control.
     *
     * @param item The item to delete the GACs and UACs for.
     *
     * @throws SQLException Thrown if there is a problem deleting the controls.
     */

    @Override
	public void deleteAllForItem(final AccessControledObject item)
    	throws SQLException {
    	UserAccessControlDAO.getInstance().deleteAllForItem(item);
    	GroupAccessControlDAO.getInstance().deleteAllForItem(item);
    }


    private static final class InstanceHolder {
        static final AccessControlDAOUserPrecedent INSTANCE = new AccessControlDAOUserPrecedent();
    }

    public static AccessControlDAOUserPrecedent getInstance() {
        return InstanceHolder.INSTANCE;
    }
}
