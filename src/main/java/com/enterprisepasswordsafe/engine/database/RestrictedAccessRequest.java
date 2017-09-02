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

import java.sql.ResultSet;
import java.sql.SQLException;

import com.enterprisepasswordsafe.engine.utils.DateFormatter;
import com.enterprisepasswordsafe.engine.utils.IDGenerator;
import com.enterprisepasswordsafe.proguard.ExternalInterface;

public final class RestrictedAccessRequest implements ExternalInterface {

	/**
	 * The ID of this request.
	 */
	private String requestId;

	/**
	 * The ID of the item involved in the request.
	 */
	private String itemId;

	/**
	 * The ID of the user involved in the request.
	 */
	private String requesterId;

	/**
	 * The ID of the approvers list for the request.
	 */
	private final String approversListId;

	/**
	 * The date and time the request expires.
	 */
	private long requestDT;

	/**
	 * The date and time the item was viewed
	 */
	private long viewedDT;

	/**
	 * The reason for viewing the item.
	 */
	private String reason;

	/**
	 * The lifetime of this RA request.
	 */

	private int lifetime;

	/**
	 * Constructor. Creates the request from the database data.
	 *
	 * @param rs The ResultSet to extract the data from.
	 */
	public RestrictedAccessRequest(ResultSet rs, int theLifetime)
		throws SQLException {
		int idx = 1;
		requestId = rs.getString(idx++);
		itemId = rs.getString(idx++);
		requesterId = rs.getString(idx++);
		approversListId = rs.getString(idx++);
		requestDT = rs.getLong(idx++);
		viewedDT = rs.getLong(idx++);
		reason = rs.getString(idx);
		lifetime = theLifetime;
	}

	/**
	 * Constructor. Stores information.
	 */

	public RestrictedAccessRequest( final String theItemId,
			final String theRequesterId, final String theReason,
			final String theApproversListId)
		throws SQLException {
		requestId = IDGenerator.getID();
		itemId = theItemId;
		requesterId = theRequesterId;
		reason = theReason;
		requestDT = DateFormatter.getNow();
		approversListId = theApproversListId;
	}

	/**
	 * Test to see if this request has expired.
	 *
	 * @return true if the request has expired, false if not.
	 */

	public boolean hasExpired()
		throws SQLException {
		long requestCutoff = DateFormatter.getTimeInPast(lifetime);
		return requestDT < requestCutoff;
	}

	public String getItemId() {
		return itemId;
	}

	public void setItemId(String newItemId) {
		itemId = newItemId;
	}

	public String getReason() {
		return reason;
	}

	public void setReason(String reason) {
		this.reason = reason;
	}

	public long getRequestDT() {
		return requestDT;
	}

	public void setRequestDT(long requestDT) {
		this.requestDT = requestDT;
	}

	public String getRequesterId() {
		return requesterId;
	}

	public void setRequesterId(String requesterId) {
		this.requesterId = requesterId;
	}

	public String getRequestId() {
		return requestId;
	}

	public void setRequestId(String requestId) {
		this.requestId = requestId;
	}

	public long getViewedDT() {
		return viewedDT;
	}

	public void setViewedDT(final long newViewedDT) {
		viewedDT = newViewedDT;
	}

	public String getApproversListId() {
		return approversListId;
	}
}
