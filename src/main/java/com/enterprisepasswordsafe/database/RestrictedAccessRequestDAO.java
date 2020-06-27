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

import com.enterprisepasswordsafe.database.AccessRole.ApproverSummary;
import com.enterprisepasswordsafe.engine.utils.DateFormatter;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public final class RestrictedAccessRequestDAO {

	private static final String SQL_FIELDS =
		"request_id, item_id, requester_id, approvers_list_id, request_dt_l, viewed_dt_l, reason";

	private static final String GET_SQL =
			"SELECT " + SQL_FIELDS + " FROM ra_requests WHERE request_id = ? ";

	private static final String GET_VALID_REQUEST =
		"SELECT " + SQL_FIELDS + " FROM ra_requests WHERE item_id = ? " +
		"   AND requester_id = ? AND (request_dt_l > ? OR (viewed_dt_l IS NOT NULL AND viewed_dt_l > ?)) ";

	private static final String GET_OUTSTANDING_REQUESTS =
		"SELECT rar.request_id, rar.item_id, rar.requester_id, rar.approvers_list_id, " +
		"		rar.request_dt_l, rar.viewed_dt_l, rar.reason "+
		"  FROM ra_requests rar, ra_approver_lists ral " +
		" WHERE (rar.request_dt_l > ? OR (rar.viewed_dt_l IS NOT NULL AND rar.viewed_dt_l > ?)) " +
		"   AND ral.list_id = rar.approvers_list_id AND ral.user_id = ?";

	private static final String SET_VIEWED_DT =
		"UPDATE ra_requests SET viewed_dt_l = ? WHERE request_id = ?";

	private static final String INSERT_SQL =
		"INSERT INTO ra_requests (request_id, item_id, requester_id, approvers_list_id, request_dt_l, reason) "+
		" VALUES (         ?,       ?,            ?,                 ?,            ?,      ?)";

	private RestrictedAccessRequestDAO( ) {
		super();
	}

	private int getRARLifetime()
		throws SQLException{
		String storedLifetime = ConfigurationDAO.getValue(ConfigurationOption.RAR_LIFETIME);
		return Integer.parseInt(storedLifetime) * 60;
	}

	public RestrictedAccessRequest create ( final String itemId,
			final String requesterId, final String reason, final String ignoreUserId)
		throws SQLException {
		Set<ApproverSummary> approvers = AccessRoleDAO.getInstance().getApprovers(itemId, ignoreUserId);
		String approversListId = ApproverListDAO.getInstance().initialiseList(approvers);

		RestrictedAccessRequest rar =
			new RestrictedAccessRequest(itemId, requesterId, reason, approversListId);
		store(rar);
		return rar;
	}

	public void store(RestrictedAccessRequest rar)
		throws SQLException {
		try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(INSERT_SQL)) {
			ps.setString(1, rar.getRequestId());
			ps.setString(2, rar.getItemId());
			ps.setString(3, rar.getRequesterId());
			ps.setString(4, rar.getApproversListId());
			ps.setLong  (5, rar.getRequestDT());
			ps.setString(6, rar.getReason());
			ps.executeUpdate();
		}
	}

	public RestrictedAccessRequest getValidRequest( final String itemId, final String requesterId)
		throws SQLException {
		long requestCutoff = DateFormatter.getTimeInPast(getRARLifetime());
		try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_VALID_REQUEST)) {
			ps.setString(1, itemId);
			ps.setString(2, requesterId);
			ps.setLong  (3, requestCutoff);
			ps.setLong  (4, requestCutoff);
			try(ResultSet rs = ps.executeQuery()) {
				return rs.next() ? new RestrictedAccessRequest(rs, getRARLifetime()) : null;
			}
		}
	}

	public RestrictedAccessRequest getById( final String id )
		throws SQLException {
		try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_SQL)) {
			ps.setString(1, id);
			ps.setMaxRows(1);
			try(ResultSet rs = ps.executeQuery()) {
				return rs.next() ? new RestrictedAccessRequest(rs, getRARLifetime()) : null;
			}
		}
	}

	public void setViewedDT(RestrictedAccessRequest rar,  final long newViewedDT)
	throws SQLException {
		try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(SET_VIEWED_DT)) {
			ps.setLong  (1, newViewedDT);
			ps.setString(2, rar.getRequestId());
			ps.executeUpdate();

			rar.setViewedDT(newViewedDT);
		}
	}

	public List<RestrictedAccessRequest> getRARsForUser(final User user)
	throws SQLException {
		List<RestrictedAccessRequest> rars = new ArrayList<>();

		int rarLifetime = getRARLifetime();
		long requestCutoff = DateFormatter.getTimeInPast(rarLifetime);
		try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_OUTSTANDING_REQUESTS)) {
			ps.setLong  (1, requestCutoff);
			ps.setLong  (2, requestCutoff);
			ps.setString(3, user.getId());
			try(ResultSet rs = ps.executeQuery()) {
				while (rs.next()) {
					rars.add(new RestrictedAccessRequest(rs, rarLifetime));
				}

				return rars;
			}
		}
	}

    //------------------------

	private static final class InstanceHolder {
		final static RestrictedAccessRequestDAO INSTANCE = new RestrictedAccessRequestDAO();
	}

    public static RestrictedAccessRequestDAO getInstance() {
    	return InstanceHolder.INSTANCE;
    }
}
