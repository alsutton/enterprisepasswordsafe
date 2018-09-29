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


import com.enterprisepasswordsafe.engine.logging.LogEventHasher;
import com.enterprisepasswordsafe.proguard.JavaBean;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Calendar;

/**
 * Object representing an entry in the event log.
 */
public final class TamperproofEventLog
    implements JavaBean {

	/**
	 * Dummy userId - Used to indicate no user was involved.
	 */

	public static final String DUMMY_USER_ID = "-1";

    /**
     * The various log levels available.
     */

    public static final String	LOG_LEVEL_AUTHENTICATION = "authentication",
    							LOG_LEVEL_CONFIGURATION = "configuration",
    							LOG_LEVEL_REPORTS = "reports",
								LOG_LEVEL_USER_MANIPULATION = "user_manipulation",
    							LOG_LEVEL_GROUP_MANIPULATION = "group_manipulation",
    							LOG_LEVEL_OBJECT_MANIPULATION = "object_manipulation",
    							LOG_LEVEL_HIERARCHY_MANIPULATION = "hierarchy_manipulation";

    /**
     * The date and time of the event.
     */

    private long datetime;

    /**
     * The ID of the item involved in the event.
     */

    private String itemId;

    /**
     * The ID of the user involved.
     */

    private String userId;

    /**
     * Details of what happened.
     */
    private final String event;

    /**
     * The tamperproof stamp.
     */

    private byte[] tamperStamp;

    /**
     * Creates a new instance of EventLog.
     *
     * @param newUser
     *            The user involved with the event.
     * @param newEvent
     *            The details of the event itself.
     * @param createTamperstamp
     *            True if a tamperstamp should be created, false if not.
     *
     * @throws GeneralSecurityException Thrown if there is a problem creating the tamperstamp.
     * @throws UnsupportedEncodingException
     */

    public TamperproofEventLog(final User newUser,
    		final AccessControledObject item,
            final String newEvent,
            final boolean createTamperstamp)
        throws GeneralSecurityException, UnsupportedEncodingException {

    	Calendar cal = Calendar.getInstance();
        datetime = cal.getTimeInMillis();
        if( newUser != null ) {
        	userId = newUser.getId();
        }
        event = newEvent;

        if( item != null ) {
        	itemId = item.getId();
        }

        if (createTamperstamp) {
            tamperStamp = new LogEventHasher().createTamperstamp(newUser, this);
        } else {
            tamperStamp = null;
        }
    }

    public TamperproofEventLog(final ResultSet rs, final int startIdx)
            throws SQLException {
        int currentIdx = startIdx;
        datetime = rs.getLong(currentIdx++);
        userId = rs.getString(currentIdx++);
        itemId = rs.getString(currentIdx++);
        event = rs.getString(currentIdx++);
        tamperStamp = rs.getBytes(currentIdx);

        if (userId.equals(DUMMY_USER_ID)) {
        	userId = null;
        }
    }

    /**
     * Returns whether or not this entry has a tamperproof stamp.
     *
     * @return True if the entry has a tamperproof stamp, false if not.
     */

    public boolean hasTamperstamp() {
        return tamperStamp != null;
    }

    /**
     * Get the date and time associated with this log entry.
     *
     * @return The date and time associated with this entry.
     */

    public long getDateTime()
    {
        return datetime;
    }

    /**
     * Set the date and time associated with this log entry.
     *
     * @param newDateTime The date and time to use.
     */

    public void setDateTime(long newDateTime)
    {
        datetime = newDateTime;
    }

    /**
     * @return Returns the user ID.
     */
    public final String getUserId() {
        return userId;
    }

    /**
     * Get the event.
     *
     * @return The event.
     */
	public String getEvent() {
		return event;
	}

	/**
	 * Get the tamperstamp for the entry.
	 *
	 * @return The tamperstamp.
	 */
	public byte[] getTamperStamp() {
		return tamperStamp;
	}

	/**
	 * Get the ID of the item involved in the event.
	 *
	 * @return The ID of the item involved in the event.
	 */
	public String getItemId() {
		return itemId;
	}

	/**
	 * Set the ID of the item involved in the event.
	 *
	 * @param newItemId The ID of the item involved in the event.
	 */
	public void setItemId(String newItemId) {
		itemId = newItemId;
	}
}
