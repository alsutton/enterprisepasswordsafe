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

/*
 * EventLog.java
 *
 * Created on 08 July 2003, 16:12
 */

package com.enterprisepasswordsafe.engine.database;

import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.engine.logging.LogEventHasher;
import com.enterprisepasswordsafe.engine.logging.LogEventParser;
import com.enterprisepasswordsafe.engine.users.UserClassifier;
import com.enterprisepasswordsafe.engine.utils.PasswordUtils;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Object representing an entry in the event log.
 */
public final class ExpandedTamperproofEventLogEntry
		implements Comparable<ExpandedTamperproofEventLogEntry> {

	private static final String LOG_TAG = "DB::ETEF";

	public enum Status {
		UNKNOWN(-1),
		OK(0),
		INVALID(1);

		private final int numericValue;

		Status(int numericValue) {
			this.numericValue = numericValue;
		}
	}

	private final String event;

	private final String humanReadableMessage;

	private final Calendar timestamp;

	private boolean historyStored;

	private final byte[] tamperstamp;

	private final String itemId;

	private Status tamperstampStatus;

	private String username;

	private String item;

	private final UserClassifier userClassifier;
	private final LogEventHasher logEventHasher;
	private final AccessControlDAO accessControlDAO;

	public static ExpandedTamperproofEventLogEntry from(final ResultSet rs, final User user, final Group adminGroup,
														final boolean validateTamperstamp) throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
		return new ExpandedTamperproofEventLogEntry(new UserClassifier(), new LogEventHasher(), new LogEventParser(),
				AccessControlDAO.getInstance(), UserDAO.getInstance(), new PasswordUtils<>(), rs, user, adminGroup,
				validateTamperstamp);
	}

	ExpandedTamperproofEventLogEntry(final UserClassifier userClassifier, final LogEventHasher logEventHasher,
									 final LogEventParser logEventParser, final AccessControlDAO accessControlDAO,
									 final UserDAO userDAO, final PasswordUtils<Password> passwordUtils, final ResultSet rs,
									 final User validatingUser, final Group adminGroup,
									 boolean validateTamperstamp)
			throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
		this.userClassifier = userClassifier;
		this.logEventHasher = logEventHasher;
		this.accessControlDAO = accessControlDAO;

		long dateTime = rs.getLong(1);
		timestamp = Calendar.getInstance();
		timestamp.setTimeInMillis(dateTime);
		String userId = rs.getString(2);
		itemId = rs.getString(3);
		event = rs.getString(4);
		tamperstamp = rs.getBytes(5);
		username = rs.getString(6);
		humanReadableMessage = logEventParser.getParsedMessage(event);

		if (validateTamperstamp && userId != null) {
			testTamperstamp(userDAO.getByIdDecrypted(userId, adminGroup), dateTime, itemId);
		} else {
			tamperstampStatus = Status.UNKNOWN;
		}

		if (itemId != null) {
			populateObjectDetails(rs, validatingUser, passwordUtils);
		}
	}

	private void populateObjectDetails(ResultSet rs, User validatingUser, PasswordUtils<Password> passwordUtils)
			throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
		AccessControl ac = accessControlDAO.getReadAccessControl(validatingUser, itemId);
		if (ac == null) {
			return;
		}

		Password pass;
		try {
			pass = passwordUtils.decrypt(ac, rs.getBytes(7));
			item = pass.getUsername() + " @ " + pass.getLocation();
		} catch (Exception e) {
			Logger.getLogger(LOG_TAG).log(Level.SEVERE, "Problem fetching object", e);
			item = "";
		}

		String booleanFlag = rs.getString(8);
		historyStored = (booleanFlag != null && booleanFlag.equals("Y"));
	}

	/**
	 * Get the description of the item involved in the event.
	 *
	 * @return The description of the item involved in the event message.
	 */
	public String getItem() {
		return item;
	}

	public boolean isHistoryStored() {
		return historyStored;
	}

	public String getItemId() {
		return itemId;
	}

	public Status getTamperstampStatus() {
		return tamperstampStatus;
	}

	public void setTamperstampStatus(Status newState) {
		tamperstampStatus = newState;
	}

	public final void testTamperstamp(final User logUser, final long datetime, final String itemId)
			throws GeneralSecurityException {
		if (logUser == null || tamperstamp == null || userClassifier.isMasterAdmin(logUser)) {
			setTamperstampStatus(Status.UNKNOWN);
			return;
		}

		byte[] stampHash = logEventHasher.createTamperstamp(logUser,
				datetime, event, itemId, logUser.getId());
		if (Arrays.equals(tamperstamp, stampHash)) {
			setTamperstampStatus(Status.OK);
		} else {
			setTamperstampStatus(Status.INVALID);
		}
	}

	public long getDateTime() {
		return timestamp.getTimeInMillis();
	}

    public Date getDate() {
        return timestamp.getTime();
    }

    public byte[] getTamperStamp() {
		return tamperstamp;
	}

    public String getHumanReadableMessage() {
		return humanReadableMessage;
	}

	@Override
	public String toString() {
		return humanReadableMessage;
	}

	public String getUsername() {
		return username;
	}

	/**
     * Compare this to another expanded tamper proof log entry
     */
	@Override
	public int compareTo(ExpandedTamperproofEventLogEntry otherEntry) {
		return (int)(getDateTime()-otherEntry.getDateTime());
	}
}
