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

import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Role for a group and item.
 */
public class GroupAccessRole extends AccessRole {

	/**
	 * Pass through storage constructor.
	 * 
	 * @param theItemId The ID of the item involved.
	 * @param theActorId The ID of the group involved.
	 * @param theRole The role.
	 */
	public GroupAccessRole(String theItemId, String theActorId,
			String theRole) {
		super(theItemId, theActorId, theRole);
	}

	/**
	 * Pass through constructor.
	 * 
	 * @param rs The ResultSet to extract the data from.
	 * @param startIdx The start index of the role details.
	 * 
	 * @throws SQLException The exception thrown if there is a problem accessing the database.
	 */
	public GroupAccessRole(ResultSet rs, int startIdx) throws SQLException {
		super(rs, startIdx);
	}

}
