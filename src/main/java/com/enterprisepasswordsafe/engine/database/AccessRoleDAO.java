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
import java.util.HashSet;
import java.util.Set;

import com.enterprisepasswordsafe.engine.database.AccessRole.ApproverSummary;

/**
 * Data access object for the user objects.
 */
public final class AccessRoleDAO {

	/**
	 * The SQL to get an access role for a particular actor
	 */

	protected static final String ACCESS_ROLE_FIELDS = "item_id, actor_id, role";

	/**
	 * The SQL to get the users which can approve access to a item via their groups.
	 */

	private static final String GET_APPROVERS_VIA_GROUPS_SQL =
			"SELECT usrs.user_id, usrs.email "+
			"FROM	application_users usrs, "+
			"		membership mbr, " +
			"		group_access_roles gar, " +
			"		groups grp "+
			"WHERE	gar.role = '"+AccessRole.APPROVER_ROLE+"' " +
			"  AND	gar.item_id = ? " +
			"  AND  gar.actor_id = grp.group_id" +
            "  AND  grp.status = " + Group.STATUS_ENABLED +
			"  AND  mbr.group_id = gar.actor_id" +
			"  AND  usrs.user_id = mbr.user_id";

	/**
	 * The SQL to get the users which can approve access to a item.
	 */

	private static final String GET_APPROVERS_SQL =
			"SELECT usrs.user_id, usrs.email "+
			"FROM	application_users usrs, "+
			"		user_access_roles uar " +
			"WHERE	uar.role = '"+AccessRole.APPROVER_ROLE+"' " +
			"  AND	uar.item_id = ? " +
			"  AND  usrs.user_id = uar.actor_id" +
            "  AND (usrs.disabled is null OR usrs.disabled = 'N')";

	/**
	 * Check if a user has a specific role.
	 */

	private static final String CHECK_DIRECT_ROLE_SQL =
			"SELECT actor_id "+
			"FROM	user_access_roles " +
			"WHERE	role = ?" +
			"  AND	item_id = ? " +
			"  AND  actor_id = ?";

	/**
	 * Check if a user has a specific role.
	 */

	private static final String CHECK_INDIRECT_ROLE_SQL =
			"SELECT gar.actor_id "+
			"FROM	group_access_roles gar," +
			"		membership mbr, " +
			"		groups grp "+
			"WHERE	gar.role = ?" +
			"  AND	gar.item_id = ? " +
			"  AND  mbr.user_id = ? " +
			"  AND  gar.actor_id = mbr.group_id "+
			"  AND  grp.group_id = mbr.group_id "+
            "  AND  grp.status = " + Group.STATUS_ENABLED;


	/**
	 * Private constructor to prevent instantiation.
	 */

	private AccessRoleDAO( ) {
		super();
	}


	/**
	 * Get a Set of approver email addresses.
	 *
	 * @param id The id of the item to get the approvers for.
     * @param ignoreUserId The ID of a user to exclude from the results.
	 */

	public Set<ApproverSummary> getApprovers( String id, String ignoreUserId )
		throws SQLException {
		HashSet<ApproverSummary> approvers = new HashSet<>();

		addApproversToSet(approvers, GET_APPROVERS_VIA_GROUPS_SQL, id);
		addApproversToSet(approvers, GET_APPROVERS_SQL, id);

		if(ignoreUserId != null) {
	        ApproverSummary remoteUserSummary = new ApproverSummary(ignoreUserId, null);
	        approvers.remove(remoteUserSummary);
		}

		return approvers;
	}

	/**
	 * Performs a query and adds the results of a set.
	 *
	 * @param approvers The set of approvers to add to.
	 * @param sql The SQL to get the approvers for.
	 * @param id The ID of the item to get the approvers for.
	 */

	private void addApproversToSet( final Set<ApproverSummary> approvers,
			final String sql, final String id)
		throws SQLException {
		try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql)) {
			ps.setString(1, id);

			try(ResultSet rs = ps.executeQuery()) {
				while( rs.next() ) {
					int idx = 1;
					String approverId = rs.getString(idx++);
					String approverEmail = rs.getString(idx);
					approvers.add(new ApproverSummary(approverId, approverEmail));
				}
			}

		}
	}

	/**
	 * Check to see if a user has role.
	 */

	public boolean hasRole(final String userId, final String itemId, final String role)
		throws SQLException {
		try (PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(CHECK_DIRECT_ROLE_SQL)) {
			ps.setString(1, role);
			ps.setString(2, itemId);
			ps.setString(3, userId);

			try (ResultSet rs = ps.executeQuery()) {
				if( rs.next() ) {
					return true;
				}
			}

		}

		try ( PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(CHECK_INDIRECT_ROLE_SQL) ) {
			ps.setString(1, role);
			ps.setString(2, itemId);
			ps.setString(3, userId);
			try ( ResultSet rs = ps.executeQuery() ) {
				return rs.next();
			}
		}
	}


    private static final class InstanceHolder {
        private static final AccessRoleDAO INSTANCE = new AccessRoleDAO();
    }

    public static AccessRoleDAO getInstance() {
		return InstanceHolder.INSTANCE;
    }
}
