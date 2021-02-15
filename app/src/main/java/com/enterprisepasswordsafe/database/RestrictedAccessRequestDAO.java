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

import com.enterprisepasswordsafe.model.AccessRoles.ApproverSummary;
import com.enterprisepasswordsafe.model.ConfigurationOptions;
import com.enterprisepasswordsafe.model.dao.AccessRoleDAO;
import com.enterprisepasswordsafe.model.persisted.ConfigurationOption;
import com.enterprisepasswordsafe.model.persisted.RestrictedAccessRequest;
import com.enterprisepasswordsafe.engine.utils.DateFormatter;

import javax.persistence.EntityManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public final class RestrictedAccessRequestDAO {

	private static final String SQL_FIELDS =
		"request_id, item_id, requester_id, approvers_list_id, request_dt_l, viewed_dt_l, reason";

	private static final String GET_VALID_REQUEST =
		"SELECT rar FROM RestrictedAccessRequest WHERE item_id = ? " +
		"   AND requester_id = ? AND (request_dt_l > ? OR (viewed_dt_l IS NOT NULL AND viewed_dt_l > ?)) ";

	private static final String GET_OUTSTANDING_REQUESTS =
		"SELECT rar FROM RestrictedAccessRequest rar " +
		" WHERE (rar.request_dt_l > ? OR (rar.viewed_dt_l IS NOT NULL AND rar.viewed_dt_l > ?)) " +
		"   AND ral.list_id = rar.approvers_list_id AND ral.user_id = ?";

	private EntityManager entityManager;

	private RestrictedAccessRequestDAO(EntityManager entityManager) {
		this.entityManager = entityManager;
	}

	private long getRARLifetime() {
		String storedLifetime = ConfigurationOption.fetchOrDefault(entityManager, ConfigurationOptions.RAR_LIFETIME);
		return TimeUnit.MINUTES.convert(Long.parseLong(storedLifetime), TimeUnit.SECONDS);
	}

	public RestrictedAccessRequest create (final Password password,
										   final User requester,
										   final String reason,
										   final String ignoreUserId)
		throws SQLException {
		Set<ApproverSummary> approvers = AccessRoleDAO.getInstance().getApprovers(itemId, ignoreUserId);


		String approversListId = ApproverListDAO.getInstance().initialiseList(approvers);

		RestrictedAccessRequest rar =
			new RestrictedAccessRequest(itemId, requesterId, reason, approversListId);
		store(rar);
		return rar;
	}

	public void store(EntityManager entityManager, RestrictedAccessRequest rar)
		throws SQLException {
		entityManager.persist(rar);
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

	public RestrictedAccessRequest getById( final Long id )
		throws SQLException {
		return entityManager.find(RestrictedAccessRequest.class, id);
	}

	public void setViewedDT(RestrictedAccessRequest rar,  final Date newViewedDT) {
		rar.setViewedTimestamp(newViewedDT);
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
}
