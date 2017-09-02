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

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

import com.enterprisepasswordsafe.engine.utils.PasswordUtils;
import com.enterprisepasswordsafe.proguard.JavaBean;

/**
 * Object representing an entry in the event log.
 */
public final class ExpandedTamperproofEventLogEntry
	implements Comparable<ExpandedTamperproofEventLogEntry>, JavaBean {

    private static final int TAMPERSTAMP_STATUS_UNKNOWN = -1,
            				 TAMPERSTAMP_STATUS_OK = 0,
            				 TAMPERSTAMP_STATUS_INVALID = 1;

    private final String event;

	private final String humanReadableMessage;

	private final Calendar timestamp;

	private boolean historyStored;

	private final byte[] tamperstamp;

	private final String itemId;

	private int tamperstampStatus;

	private String username;

	private String item;

	public ExpandedTamperproofEventLogEntry( final ResultSet rs, final User validatingUser,
			final Group adminGroup, boolean validateTamperstamp,
			final Map<String, User> userCache)
		throws SQLException, UnsupportedEncodingException, GeneralSecurityException
	{
		long dateTime = rs.getLong(1);
        timestamp = Calendar.getInstance();
        timestamp.setTimeInMillis(dateTime);
		String userId = rs.getString(2);
		itemId = rs.getString(3);
		event = rs.getString(4);
		tamperstamp = rs.getBytes(5);
		username = rs.getString(6);
		humanReadableMessage = TamperproofEventLogDAO.getInstance().getParsedMessage(event);

		if( validateTamperstamp ) {
			if( userId != null ) {
				User logUser = userCache.get(userId);
				if(logUser == null) {
					logUser = UserDAO.getInstance().getByIdDecrypted(userId, adminGroup);
					if( logUser != null) {
						userCache.put(userId, logUser);
					}
				}
				testTamperstamp(logUser, dateTime, itemId);
			}
		}

		if(itemId != null ) {
            AccessControlDAO acDAO = AccessControlDAO.getInstance();
            AccessControl ac = acDAO.getReadAccessControl(validatingUser, itemId);
            if (ac != null) {
                Password pass = new Password();
                try {
                    PasswordUtils.decrypt(pass, ac, rs.getBytes(7));
                    item = pass.getUsername() + " @ " + pass.getLocation();
                } catch (Exception ioe) {
                    item = "";
                }

                String booleanFlag = rs.getString(8);
                historyStored = (booleanFlag != null && booleanFlag.equals("Y"));
            }
		}

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

	public int getTamperstampStatus() {
		return tamperstampStatus;
	}

	public void setTamperstampStatus( int newState ) {
		tamperstampStatus = newState;
	}

    public final void testTamperstamp(final User logUser, final long datetime, final String itemId)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	if( logUser == null
    	||	tamperstamp == null
    	||  User.ADMIN_USER_ID.equals(logUser.getUserId())) {
    		setTamperstampStatus( TAMPERSTAMP_STATUS_UNKNOWN );
    		return;
    	}
        String tamperStampData =
        	TamperproofEventLogDAO.
        		createTamperstampString(datetime, event, itemId, logUser.getUserId());
        byte[] stampHash = createHash(tamperStampData);
        stampHash = logUser.encrypt(stampHash);

        if (Arrays.equals(tamperstamp, stampHash)) {
        	setTamperstampStatus( TAMPERSTAMP_STATUS_OK );
        } else {
        	setTamperstampStatus( TAMPERSTAMP_STATUS_INVALID );
        }
    }

    private byte[] createHash(final String value)
        throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest digester = MessageDigest
                .getInstance(TamperproofEventLog.TAMPERSTAMP_HASH_ALGORITHM);
        digester.update(value.getBytes());
        return digester.digest();
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
