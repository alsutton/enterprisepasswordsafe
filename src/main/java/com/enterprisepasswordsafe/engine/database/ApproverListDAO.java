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
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import com.enterprisepasswordsafe.engine.utils.DateFormatter;
import com.enterprisepasswordsafe.engine.utils.IDGenerator;
import com.enterprisepasswordsafe.proguard.ExternalInterface;

/**
 * Data access object for the user objects.
 */

public final class ApproverListDAO implements ExternalInterface {

	/**
	 * SQL to count the number of approvers in this list.
	 */

	private static final String GET_APPROVER_COUNT =
		"SELECT count(*) "+
		"  FROM ra_approver_lists "+
		" WHERE approval_state = '"+ApproverList.APPROVER_FLAG+"' "+
		"   AND list_id = ?";

	/**
	 * SQL to get the names of the users who are listed as appovers in an
	 * approval request.
	 */

	private static final String GET_APPROVER_NAMES =
		"SELECT usrs.user_name, usrs.full_name "+
		"  FROM ra_approver_lists ral," +
		" 		application_users usrs "+
		" WHERE ral.approval_state = '"+ApproverList.APPROVER_FLAG+"' "+
		"   AND ral.list_id = ? "+
		"   AND ral.user_id = usrs.user_id";

	/**
	 * SQL to get the names of the users who are listed as appovers in an
	 * approval request.
	 */

	private static final String GET_APPROVER_IDS =
		"SELECT user_id "+
		"  FROM ra_approver_lists "+
		" WHERE approval_state = '"+ApproverList.APPROVER_FLAG+"' "+
		"   AND list_id = ? ";

	/**
	 * SQL to count the number of approvers in this list.
	 */

	private static final String GET_BLOCKER_COUNT =
		"SELECT count(*) "+
		"  FROM ra_approver_lists "+
		" WHERE approval_state = '"+ApproverList.BLOCKER_FLAG+"' "+
		"   AND list_id = ?";

	/**
	 * SQL to get the current approval state for a user.
	 */

	private static final String GET_STATE_FOR_USER_SQL =
		"SELECT approval_state "+
		"  FROM ra_approver_lists "+
		" WHERE list_id = ? "+
		"   AND user_id = ?";

	/**
	 * SQL to set the current approval state for a user.
	 */

	private static final String SET_STATE_FOR_USER_SQL =
		"UPDATE ra_approver_lists "+
		"  SET  approval_state = ?, dt_l = ?"+
		" WHERE list_id = ? "+
		"   AND user_id = ?";

	/**
	 * SQL to initialise a list.
	 */

	private static final String INITIALISE_SQL =
		"INSERT INTO ra_approver_lists (list_id, user_id, approval_state) "+
		"						VALUES (      ?,       ?, '"+ApproverList.NOT_SELECTED_FLAG+"') ";

	/**
	 * Private constructor to prevent instantiation
	 */
	private ApproverListDAO( ) {
		super();
	}


	/**
	 * Get a list of all of the names of the approvers in a list.
	 *
	 * @param listId The ID of the list to get the approvers for.
	 *
	 * @return a List of approvers as Strings.
	 */

	public List<String> getApprovers(final String listId)
		throws SQLException {
		List<String> approvers = new ArrayList<>();

		try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_APPROVER_NAMES)) {
			ps.setString(1, listId);
			try(ResultSet rs = ps.executeQuery()) {
				while( rs.next() ) {
					int idx = 1;
					String userName = rs.getString(idx++);
					String fullName = rs.getString(idx);

					StringBuilder name = new StringBuilder(userName);
					if(fullName != null && fullName.length() > 0 ) {
						name.append( " (");
						name.append(fullName);
						name.append( ")");
					}

					approvers.add(name.toString());
				}
			}
		}

		return approvers;
	}

	/**
	 * Get a list of all of the names of the approvers in a list.
	 *
	 * @param listId The ID of the list to get the approvers for.
	 *
	 * @return a List of approvers as Strings.
	 */

	public List<String> getApproverIDs(final String listId)
		throws SQLException {
		List<String> approvers = new ArrayList<>();

		try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_APPROVER_IDS)) {
			ps.setString(1, listId);
			try(ResultSet rs = ps.executeQuery()) {
				while( rs.next() ) {
					approvers.add(rs.getString(1));
				}

				return approvers;
			}
		}
	}

	/**
	 * Initialise a new list of approvers.
	 *
	 * @param approvers a Set of approvers to put into the database.
	 */

	public String initialiseList(final Set<AccessRole.ApproverSummary> approvers)
		throws SQLException {
		String id = IDGenerator.getID();

		try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(INITIALISE_SQL)) {
			for(AccessRole.ApproverSummary summary : approvers) {
				ps.setString(1, id);
				ps.setString(2, summary.getId());
				ps.addBatch();
			}
			ps.executeBatch();
		}

        return id;
	}
	/**
	 * Get the number of approvers in the list.
	 *
	 * @param listId The ID of the list to count.
	 */

	public int countApprovers(final String listId)
		throws SQLException {
		return doCount(GET_APPROVER_COUNT, listId);
	}

	/**
	 * Get the number of users who have denied the request in the list.
	 *
	 * @param listId The ID of the list to count.
	 */

	public int countBlockers(final String listId)
		throws SQLException {
		return doCount(GET_BLOCKER_COUNT, listId);
	}

	/**
	 * Method to return a count for a particular list.
	 *
	 * @param sql The SQL to run.
	 * @param listId The ID of the list to use for the SQL.
	 *
	 * @return -1 if no count was returned, or the count applicable to the query.
	 *
	 * @throws SQLException Thrown if there is a problem.
	 */

	private int doCount(final String sql, final String listId)
		throws SQLException {
		try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql)) {
			ps.setString(1, listId);
			try(ResultSet rs = ps.executeQuery()) {
				if( rs.next() ) {
					return rs.getInt(1);
				}

				return -1;
			}
		}
	}

	/**
	 * Get the approval state for a user in a list.
	 *
     * @param rar The RestrictedAccessRequest to check the state for.
     * @param user The User to check the state for.
	 *
	 * @return The approval state, or null if the user was not in the list.
	 */

	public String getApprovalStateForUser( final RestrictedAccessRequest rar, final User user)
		throws SQLException {
		try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_STATE_FOR_USER_SQL)) {
			int idx = 1;
			ps.setString(idx++, rar.getApproversListId());
			ps.setString(idx, user.getId());
			try(ResultSet rs = ps.executeQuery()) {
				if( rs.next() ) {
					return rs.getString(1);
				}

				return null;
			}
		}
	}

	/**
	 * Set the approval state for a user in a list.
	 *
     * @param rar The Restricted Access Request to set the state for.
     * @param user The user to set the state for.
	 * @param state The state to set for the user
	 */

	public void setApprovalStateForUser( final RestrictedAccessRequest rar,
			final User user, final String state)
		throws SQLException {
		try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(SET_STATE_FOR_USER_SQL)) {
			int idx = 1;
			ps.setString(idx++, state);
			ps.setLong(idx++, DateFormatter.getNow());
			ps.setString(idx++, rar.getApproversListId());
			ps.setString(idx, user.getId());
			ps.executeUpdate();
		}
	}

    //------------------------

	private static class InstanceHolder {
		static final ApproverListDAO INSTANCE = new ApproverListDAO();
	}

    public static ApproverListDAO getInstance() {
		return InstanceHolder.INSTANCE;
    }
}
