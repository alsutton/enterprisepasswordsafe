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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Object modeling a group access control.
 */

public final class GroupAccessControl extends AccessControl {
    /**
     * The group to which the GAC is relevant.
     */

    private Group group;

    /**
     * Null constructor. Useful for reusable objects.
     */

    public GroupAccessControl() {
    	super();
    }

    /**
     * Creates a new instance of GroupAccessControl.
     *
     * @param newGroupId
     *            The ID of the group to which this GAC is relevant.
     * @param newItemId
     *            The ID of the item to which this GAC is relevant.
     * @param newModifyKey
     *            The modification key for the item.
     * @param newReadKey
     *            The read key for the item.
     */
    public GroupAccessControl(final String newGroupId, final String newItemId,
            final PrivateKey newModifyKey, final PublicKey newReadKey) {
        super(newItemId, newGroupId, newModifyKey, newReadKey);
        group = null;
    }

    /**
     * Gets an instance of a GroupAccessControl using the group ID from a membership.
     *
     * @param rs
     *            The ResultSet holding the details of this GroupAccessControl.
     * @param startIdx
     *            The start index for the data.
     * @param membership
     *            The membership to which this GroupAccessControl is relevant.
     *
     * @throws SQLException Thrown if there is a problem extracting the data.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the access keys.
     * @throws UnsupportedEncodingException
     */
    public GroupAccessControl(final ResultSet rs, final int startIdx, final Group newGroup)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        super(rs, startIdx, newGroup);

        group = newGroup;
    }

    /**
     * Gets the ID of the group involved in this GAC.
     *
     * @return The ID of the group.
     */

    public String getGroupId() {
        return getAccessorId();
    }

    /**
     * Gets the group involved in this GAC.
     *
     * @return The group involved in the GAC.
     */

    public Group getGroup() {
        return group;
    }
}
