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

package com.enterprisepasswordsafe.database;

import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.engine.users.UserClassifier;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

public abstract class AccessControlDAO {

    private final UserClassifier userClassifier = new UserClassifier();

    public abstract AccessControl getAccessControl(final User user, final AccessControledObject item)
        throws GeneralSecurityException, SQLException, UnsupportedEncodingException;

    public abstract AccessControl getAccessControl(final User user, final String itemId)
        throws GeneralSecurityException, SQLException, UnsupportedEncodingException;

    public abstract AccessControl getReadAccessControl(final User user, final String itemId)
        throws GeneralSecurityException, SQLException, UnsupportedEncodingException;

    public abstract AccessControl getAccessControlEvenIfDisabled(final User user, final String itemId)
        throws GeneralSecurityException, SQLException, UnsupportedEncodingException;

    public AccessControl getAccessControlUnlockedIfAdmin(final User user, final String itemId)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        return userClassifier.isPriviledgedUser(user) ?
                AccessControlDAO.getInstance().getAccessControlEvenIfDisabled(user, itemId) :
                AccessControlDAO.getInstance().getAccessControl(user, itemId);
    }

    public abstract void deleteAllForItem(final AccessControledObject item)
    	throws SQLException;

    //------------------------

    public static AccessControlDAO getInstance()
        throws SQLException {
		String precedence = ConfigurationDAO.getValue(ConfigurationOption.PERMISSION_PRECEDENCE);

        return (precedence != null && precedence.equals("G"))
                ? AccessControlDAOGroupPrecedent.getInstance() : AccessControlDAOUserPrecedent.getInstance();
    }
}
