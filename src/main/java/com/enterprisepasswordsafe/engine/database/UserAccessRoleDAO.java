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

/**
 * Data access object for UserAccessRole objects.
 */

public class UserAccessRoleDAO implements ExternalInterface{

	/**
	 * SQL to get all of the roles for a item.
	 */

	private static final String GET_ALL_SQL =
			"SELECT actor_id, role FROM user_access_roles WHERE item_id = ? ";

	/**
	 * SQL to get the UAR for a user and item.
	 */

	private static final String GET_SQL =
			"select role FROM user_access_roles WHERE item_id = ? AND actor_id = ?";

	/**
	 * SQL to store the data via an insert.
	 */

	private static final String INSERT_SQL =
			"INSERT INTO user_access_roles(item_id, actor_id, role) VALUES (?, ?, ?)";

	/**
	 * SQL to store the data via an update.
	 */

	private static final String UPDATE_SQL =
			"UPDATE user_access_roles "+
			"   SET role     = ? " +
			" WHERE actor_id = ? AND item_id = ?";

	/**
	 * SQL to store the data via an update.
	 */

	private static final String DELETE_SQL =
			"DELETE FROM user_access_roles "+
			"      WHERE item_id  = ?" +
			"        AND actor_id = ?" +
			"        AND role     = ?";

	/**
	 * Private constructor to prevent instantiation
	 */

	private UserAccessRoleDAO( ) {
		super();
	}

	/**
	 * Create a new user access role.
	 *
	 */

	public UserAccessRole create(final String itemId, final String actorId,
			final String role)
		throws SQLException {
		UserAccessRole uar = new UserAccessRole(itemId, actorId, role);
		store(uar);
		return uar;
	}

	/**
	 * Create a new user access role.
	 *
	 */

	public void delete(final String itemId, final String actorId,
			final String role)
		throws SQLException {
		PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_SQL);
		try {
			ps.setString(1, itemId);
			ps.setString(2, actorId);
			ps.setString(3, role);
			ps.executeUpdate();
		} finally {
			DatabaseConnectionUtils.close(ps);
		}

	}

	/**
	 * Store this access role in the database.
	 *
	 * @param role The UserAccessRole to store.
	 *
	 * @throws SQLException Thrown if there is a problem accessing the database.
	 */

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

	/**
	 * Update a UserAccessRole in the database.
	 *
	 * @param role The UserAccessRole to update.
	 *
	 * @throws SQLException Thrown if there is a problem accessing the database.
	 */

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

	/**
	 * Gets a UserAccessRole for a item and user
	 *
	 * @param itemId The ID of the item to get the UserAccessRole for.
	 * @param actorId The ID of the user to get the UserAccessRole for.
	 *
	 * @throws SQLException Thrown if there is a problem talking to the database.
	 */

	public UserAccessRole getByIds(final String itemId, final String actorId)
		throws SQLException {
		PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_SQL);
		try {
			ps.setString(1, itemId);
			ps.setString(2, actorId);
			ps.setMaxRows(1);
			ResultSet rs = ps.executeQuery();
			try {
				if( rs.next() ) {
					return new UserAccessRole(itemId, actorId, rs.getString(1));
				}

				return null;
			} finally {
				DatabaseConnectionUtils.close(rs);
			}
		} finally {
			DatabaseConnectionUtils.close(ps);
		}
	}

	/**
	 * Get all of the rights for a item as a Map of the user ID to the
	 * role.
	 *
	 * @param id The ID of the item to get the roles for.
	 *
	 * @throws SQLException Thrown if there is a problem talking to the database.
	 */

	public Map<String,String> getAllForItem(final String id)
		throws SQLException {
		Map<String,String> results = new HashMap<String,String>();

		PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_ALL_SQL);
		try {
			ps.setString(1, id);

			ResultSet rs = ps.executeQuery();
			try {
				while( rs.next() ) {
					String actorId = rs.getString(1);
					String role = rs.getString(2).intern();
					results.put(actorId, role);
				}

				return results;
			} finally {
				DatabaseConnectionUtils.close(rs);
			}
		} finally {
			DatabaseConnectionUtils.close(ps);
		}
	}

    //------------------------

    private static final class InstanceHolder {
    	static final UserAccessRoleDAO INSTANCE = new UserAccessRoleDAO();
    }

    public static UserAccessRoleDAO getInstance() {
		return InstanceHolder.INSTANCE;
    }
}
