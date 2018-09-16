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

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import com.enterprisepasswordsafe.engine.utils.DatabaseConnectionUtils;
import com.enterprisepasswordsafe.proguard.ExternalInterface;

public class UserAccessRoleDAO
		extends AbstractAccessRoleDAO<UserAccessRole>
		implements ExternalInterface {

	private static final String GET_ALL_SQL =
			"SELECT actor_id, role FROM user_access_roles WHERE item_id = ? ";

	private static final String GET_SQL =
			"select role FROM user_access_roles WHERE item_id = ? AND actor_id = ?";

	private static final String INSERT_SQL =
			"INSERT INTO user_access_roles(item_id, actor_id, role) VALUES (?, ?, ?)";

	private static final String UPDATE_SQL =
			"UPDATE user_access_roles SET role = ? WHERE actor_id = ? AND item_id = ?";

	private static final String DELETE_SQL =
			"DELETE FROM user_access_roles WHERE item_id = ? AND actor_id = ? AND role = ?";

	private UserAccessRoleDAO( ) {
		super(GET_ALL_SQL, GET_SQL, DELETE_SQL);
	}

	public UserAccessRole create(final String itemId, final String actorId, final String role)
		throws SQLException {
		UserAccessRole uar = new UserAccessRole(itemId, actorId, role);
		store(uar);
		return uar;
	}

	public void store( final UserAccessRole role )
		throws SQLException {
		PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(INSERT_SQL);
		try {
			ps.setString(1, role.getItemId());
			ps.setString(2, role.getActorId());
			ps.setString(3, role.getRole());
			ps.executeUpdate();
		} finally {
			DatabaseConnectionUtils.close(ps);
		}
	}

	public void update( final UserAccessRole role )
		throws SQLException {
		PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(UPDATE_SQL);
		try {
			ps.setString(1, role.getRole());
			ps.setString(2, role.getActorId());
			ps.setString(3, role.getItemId());
			ps.executeUpdate();
		} finally {
			DatabaseConnectionUtils.close(ps);
		}
	}

    @Override
    UserAccessRole newInstanceForRole(String itemId, String actorId, String role) {
        return new UserAccessRole(itemId, actorId, role);
    }

    //------------------------

    private static final class InstanceHolder {
    	static final UserAccessRoleDAO INSTANCE = new UserAccessRoleDAO();
    }

    public static UserAccessRoleDAO getInstance() {
		return InstanceHolder.INSTANCE;
    }
}
