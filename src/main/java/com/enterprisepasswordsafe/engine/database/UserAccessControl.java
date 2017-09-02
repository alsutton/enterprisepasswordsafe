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
 * Object representing a user access control.
 */
public class UserAccessControl extends AccessControl {

	/**
	 * Null constructor. Useful for creating re-usable objects.
	 */

	public UserAccessControl() {
		super();
	}

    /**
     * Creates a new instance of a UAC.
     *
     * @param newUserId The ID of the user this UAC is for.
     * @param newItemId The ID of the item this UAC is for.
     * @param newModifyKey The modification key for this UAC.
     * @param newReadKey The read key for this UAC.
     */
    public UserAccessControl(final String newUserId, final String newItemId,
            final PrivateKey newModifyKey, final PublicKey newReadKey) {
        super(newItemId, newUserId, newModifyKey, newReadKey);
    }

    /**
     * Creates an instance of the user access control from a result set.
     *
     * @param rs
     *            The ResultSet to extract the data from.
     * @param startIdx
     *            The start index in the result set where the UAC data starts.
     * @param newUser
     *            The user to whom this access control is relevant.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the data.
     * @throws UnsupportedEncodingException
     */
    public UserAccessControl(final ResultSet rs, final int startIdx, final User newUser)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        super(rs, startIdx, newUser);
    }

    /**
     * Get the ID of the user involved in this UAC.
     *
     * @return The ID of the user involved.
     */

    public String getUserId() {
        return getAccessorId();
    }
}
