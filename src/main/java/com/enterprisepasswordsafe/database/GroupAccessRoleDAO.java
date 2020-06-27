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

import java.sql.PreparedStatement;
import java.sql.SQLException;

public final class GroupAccessRoleDAO
		extends AbstractAccessRoleDAO<GroupAccessRole> {

	private static final String GET_ALL_SQL =
			"SELECT actor_id, role FROM group_access_roles WHERE item_id = ? ";

	private static final String GET_SQL =
			"select role FROM group_access_roles WHERE item_id = ? AND actor_id = ?";

	private static final String INSERT_SQL =
			"INSERT INTO group_access_roles(item_id, actor_id, role) VALUES (?, ?, ?)";

	private static final String UPDATE_SQL =
			"UPDATE group_access_roles SET actor_id = ?, role = ? WHERE item_id = ?";

	private static final String DELETE_SQL =
			"DELETE FROM group_access_roles WHERE item_id  = ? AND actor_id = ? AND role = ?";

	private GroupAccessRoleDAO(  ) {
		super(GET_ALL_SQL, GET_SQL, DELETE_SQL);
	}

	public GroupAccessRole create(final String itemId, final String actorId, final String role)
		throws SQLException {
		GroupAccessRole gar = new GroupAccessRole(itemId, actorId, role);
		store(gar);
		return gar;
	}

	public void store( final GroupAccessRole role )
		throws SQLException {
		try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(INSERT_SQL)) {
			ps.setString(1, role.getItemId());
			ps.setString(2, role.getActorId());
			ps.setString(3, role.getRole());
			ps.executeUpdate();
		}
	}

	public void update( final GroupAccessRole role )
		throws SQLException {
		try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(UPDATE_SQL)) {
			ps.setString(1, role.getActorId());
			ps.setString(2, role.getRole());
			ps.setString(3, role.getItemId());
			ps.executeUpdate();
		}
	}

	@Override
	GroupAccessRole newInstanceForRole(String itemId, String actorId, String role) {
		return new GroupAccessRole(itemId, actorId, role);
	}

	//------------------------

    private static final class InstanceHolder {
    	static final GroupAccessRoleDAO INSTANCE = new GroupAccessRoleDAO();
    }

    public static GroupAccessRoleDAO getInstance() {
    	return InstanceHolder.INSTANCE;
    }
}
